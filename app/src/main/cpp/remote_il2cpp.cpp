#include "remote_il2cpp.hpp"
#include "mem.hpp"
#include "remote_call.hpp"
#include "remote_elf.hpp"
#include "ui_log.hpp"
#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace {

struct SoModule {
    std::string path;
    uintptr_t base = 0;
    uintptr_t end = 0;
};

static std::string basename(const std::string &p) {
    const auto s = p.find_last_of('/');
    return s == std::string::npos ? p : p.substr(s + 1);
}

static bool skip_lib(const std::string &path) {
    if (path.find("/system/") != std::string::npos) return true;
    if (path.find("/apex/") != std::string::npos) return true;
    if (path.find("/vendor/") != std::string::npos) return true;
    const std::string name = basename(path);
    return name == "libdobby.so" || name == "libTool.so";
}

static void collect_modules(pid_t pid, std::vector<SoModule> &out) {
    out.clear();
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return;

    for (const auto &m : maps) {
        if (m.path.empty() || m.path[0] != '/') continue;
        if (m.path.find(".so") == std::string::npos) continue;
        if (skip_lib(m.path)) continue;
        if (m.fileOff != 0 || m.perms[0] != 'r') continue;

        bool merged = false;
        for (auto &mod : out) {
            if (mod.path == m.path) {
                mod.end = std::max(mod.end, m.end);
                merged = true;
                break;
            }
        }
        if (!merged)
            out.push_back({m.path, m.start, m.end});
    }

    std::sort(out.begin(), out.end(), [](const SoModule &a, const SoModule &b) {
        auto score = [](const std::string &n) {
            if (n.find("logic") != std::string::npos) return 100;
            if (n.find("il2cpp") != std::string::npos) return 95;
            if (n.find("csharp") != std::string::npos) return 90;
            if (n.find("GameAssembly") != std::string::npos) return 85;
            if (n.find("unity") != std::string::npos) return 50;
            return 10;
        };
        return score(basename(a.path)) > score(basename(b.path));
    });
}

static bool resolve_sym(pid_t pid, const SoModule &m, const char *sym, uintptr_t &addr) {
    addr = 0;
    if (elf_remote_sym(pid, m.base, sym, addr)) return true;
    ElfRemote er{};
    if (!elf_remote_bias(pid, m.base, er)) return false;
    return elf_file_sym(m.path.c_str(), er.load_bias, sym, addr);
}

static const char *kIl2Api[] = {
    "il2cpp_domain_get",
    "il2cpp_domain_assembly_open",
    "il2cpp_domain_get_assemblies",
    "il2cpp_class_from_name",
    "il2cpp_assembly_get_image",
    "il2cpp_image_get_class_count",
    "il2cpp_image_get_class",
    "il2cpp_class_get_field_from_name",
    "il2cpp_field_static_get_value",
    "il2cpp_thread_attach",
    "il2cpp_class_get_method_from_name",
    "il2cpp_runtime_invoke",
};

static bool domain_looks_valid(pid_t pid, uintptr_t domain);

static bool decode_adrp(uint32_t w, uint64_t pc, int64_t &pageOut) {
    if ((w & 0x9F000000u) != 0x90000000u) return false;
    int64_t immhi = (int64_t)((w >> 5) & 0x7ffffu);
    int64_t immlo = (int64_t)((w >> 29) & 0x3u);
    int64_t imm = (immhi | (immlo << 19)) << 12;
    if (w & (1u << 23)) imm |= 0xFFFFFFFFF0000000ULL;
    pageOut = (int64_t)(pc & ~0xFFFULL) + imm;
    return true;
}

static uintptr_t decode_bl_target(uint32_t w, uint64_t pc) {
    if ((w & 0xFC000000u) != 0x94000000u) return 0;
    int32_t imm26 = (int32_t)(w & 0x03FFFFFFu);
    if (imm26 & 0x02000000) imm26 |= (int32_t)0xFC000000u;
    return (uintptr_t)((int64_t)pc + ((int64_t)imm26 << 2));
}

static void probe_got_from_regs(pid_t pid, const uint64_t *x, uintptr_t &domainOut) {
    for (int r = 0; r < 31; ++r) {
        const uintptr_t addr = (uintptr_t)x[r];
        if (!mem_ptr_ok(addr)) continue;
        uintptr_t p = 0;
        if (mem_read(pid, addr, p) && domain_looks_valid(pid, p)) domainOut = p;
        if (domain_looks_valid(pid, addr)) domainOut = addr;
    }
}

static bool getter_uses_bl(pid_t pid, uintptr_t func) {
    uint32_t ins[12] = {};
    if (!mem_read(pid, func, ins, sizeof(ins))) return false;
    for (int i = 0; i < 12; ++i) {
        if ((ins[i] & 0xFC000000u) == 0x94000000u) return true;
    }
    return false;
}

static bool domain_from_getter_depth(pid_t pid, uintptr_t func, uintptr_t &domainOut, int depth) {
    domainOut = 0;
    if (!func || depth > 2) return false;
    uint32_t ins[64] = {};
    if (!mem_read(pid, func, ins, sizeof(ins))) return false;

    uint64_t x[31] = {};
    for (int i = 0; i < 60; ++i) {
        const uint32_t w = ins[i];
        const uint64_t pc = func + (uint64_t)i * 4;

        int64_t page = 0;
        if (decode_adrp(w, pc, page)) {
            const int rd = (int)(w & 0x1fu);
            if (rd >= 0 && rd < 31) x[rd] = (uint64_t)page;
        }
        if ((w & 0xFFC00000u) == 0x91000000u) {
            const int rd = (int)(w & 0x1fu);
            const int rn = (int)((w >> 5) & 0x1fu);
            uint64_t imm = (uint64_t)((w >> 10) & 0xFFFu);
            if (w & (1u << 22)) imm <<= 12;
            if (rd < 31 && rn < 31) x[rd] = x[rn] + imm;
        }
        if ((w & 0xFFC00000u) == 0xF9400000u) {
            const int rd = (int)(w & 0x1fu);
            const int rn = (int)((w >> 5) & 0x1fu);
            const uint64_t off = (uint64_t)(((w >> 10) & 0xFFFu) * 8);
            if (rd < 31 && rn < 31) {
                uintptr_t ptr = 0;
                const uintptr_t addr = (uintptr_t)(x[rn] + off);
                if (mem_read(pid, addr, ptr) && mem_ptr_ok(ptr)) {
                    x[rd] = ptr;
                    if (!domainOut) domainOut = ptr;
                }
            }
        }
        if ((w & 0xFC000000u) == 0x94000000u) {
            probe_got_from_regs(pid, x, domainOut);
            const uintptr_t blt = decode_bl_target(w, pc);
            uintptr_t subDom = 0;
            if (blt && domain_from_getter_depth(pid, blt, subDom, depth + 1) &&
                domain_looks_valid(pid, subDom))
                domainOut = subDom;
        }
        if ((w & 0xFFFFFC1Fu) == 0xD65F0000u && (w & 0x1fu) == 0x1fu) {
            if (domainOut && domain_looks_valid(pid, domainOut)) return true;
            if (domain_looks_valid(pid, (uintptr_t)x[0])) {
                domainOut = (uintptr_t)x[0];
                return true;
            }
        }
    }
    probe_got_from_regs(pid, x, domainOut);
    return domainOut != 0 && mem_ptr_ok(domainOut);
}

static bool domain_from_getter(pid_t pid, uintptr_t func, uintptr_t &domainOut) {
    return domain_from_getter_depth(pid, func, domainOut, 0);
}

static bool module_like_il2cpp(const SoModule &m) {
    const std::string n = basename(m.path);
    if (n.find("logic") != std::string::npos) return true;
    if (n.find("il2cpp") != std::string::npos) return true;
    if (n.find("csharp") != std::string::npos) return true;
    if (n.find("GameAssembly") != std::string::npos) return true;
    const bool inApp = m.path.find("/data/app/") != std::string::npos ||
                       m.path.find("/data/data/") != std::string::npos ||
                       m.path.find("/data/user/") != std::string::npos;
    return inApp;
}

static bool try_module(pid_t pid, const SoModule &m, RemoteIl2CppInfo &out, int &apiHits) {
    apiHits = 0;
    uintptr_t domainGet = 0;
    if (!resolve_sym(pid, m, "il2cpp_domain_get", domainGet) || !domainGet) return false;

    out.export_domain_get = true;
    out.base = m.base;
    out.end = m.end;
    out.sym_domain_get = domainGet;
    std::snprintf(out.libPath, sizeof(out.libPath), "%s", m.path.c_str());
    std::snprintf(out.libBaseName, sizeof(out.libBaseName), "%s", basename(m.path).c_str());

    for (const char *api : kIl2Api) {
        uintptr_t a = 0;
        if (!resolve_sym(pid, m, api, a) || !a) continue;
        ++apiHits;
        if (std::strcmp(api, "il2cpp_domain_assembly_open") == 0)
            out.sym_domain_assembly_open = a;
        if (std::strcmp(api, "il2cpp_domain_get_assemblies") == 0)
            out.sym_domain_get_assemblies = a;
        if (std::strcmp(api, "il2cpp_class_from_name") == 0)
            out.sym_class_from_name = a;
        if (std::strcmp(api, "il2cpp_assembly_get_image") == 0)
            out.sym_assembly_get_image = a;
        if (std::strcmp(api, "il2cpp_image_get_class_count") == 0)
            out.sym_image_get_class_count = a;
        if (std::strcmp(api, "il2cpp_image_get_class") == 0)
            out.sym_image_get_class = a;
        if (std::strcmp(api, "il2cpp_class_get_field_from_name") == 0)
            out.sym_class_get_field_from_name = a;
        if (std::strcmp(api, "il2cpp_field_static_get_value") == 0)
            out.sym_field_static_get_value = a;
        if (std::strcmp(api, "il2cpp_thread_attach") == 0)
            out.sym_thread_attach = a;
        if (std::strcmp(api, "il2cpp_class_get_method_from_name") == 0)
            out.sym_class_get_method_from_name = a;
        if (std::strcmp(api, "il2cpp_runtime_invoke") == 0)
            out.sym_runtime_invoke = a;
    }
    out.export_domain_get_assemblies = out.sym_domain_get_assemblies != 0;
    out.export_class_from_name = out.sym_class_from_name != 0;
    out.export_assembly_get_image = out.sym_assembly_get_image != 0;
    out.export_class_get_field_from_name = out.sym_class_get_field_from_name != 0;
    out.export_field_static_get_value = out.sym_field_static_get_value != 0;
    out.export_thread_attach = out.sym_thread_attach != 0;

    if (domain_from_getter(pid, domainGet, out.domain_ptr)) {
        std::snprintf(out.note, sizeof(out.note),
                      "conRent-style sym resolve: %d APIs, domain*=0x%llx",
                      apiHits, (unsigned long long)out.domain_ptr);
    } else {
        std::snprintf(out.note, sizeof(out.note),
                      "conRent-style sym resolve: %d APIs (domain* decode pending)",
                      apiHits);
    }
    return true;
}

static bool domain_looks_valid(pid_t pid, uintptr_t domain) {
    if (!mem_ptr_ok(domain)) return false;
    uintptr_t words[16] = {};
    if (!mem_read(pid, domain, words, sizeof(words))) return false;
    int ptrLike = 0;
    for (uintptr_t w : words)
        if (mem_ptr_ok(w)) ptrLike++;
    return ptrLike >= 2;
}

static void domain_scan_bss(pid_t pid, const RemoteIl2CppInfo &lib, uintptr_t &domainOut) {
    domainOut = 0;
    if (!lib.base) return;
    const std::string libName = lib.libBaseName[0] ? lib.libBaseName : basename(lib.libPath);
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return;
    for (const auto &m : maps) {
        if (m.start < lib.base || m.end > lib.end + 0x400000ULL) continue;
        if (m.perms[0] != 'r' || m.perms[1] != 'w') continue;
        const bool inModule = !m.path.empty() &&
                              (m.path.find(libName) != std::string::npos || m.path.find("libil2cpp") != std::string::npos ||
                               m.path.find("liblogic") != std::string::npos || m.path.empty());
        if (!inModule && m.fileOff != 0) continue;
        const size_t sz = (size_t)(m.end - m.start);
        for (size_t off = 0; off < sz; off += 512 * sizeof(uintptr_t)) {
            uintptr_t cand = 0;
            if (!mem_read(pid, m.start + off, cand)) continue;
            if (!domain_looks_valid(pid, cand)) continue;
            domainOut = cand;
            return;
        }
    }
}

static pid_t g_il2CachedPid = 0;
static RemoteIl2CppInfo g_il2Cached{};

} // namespace

bool remote_il2cpp_domain_get_uses_bl(pid_t pid, uintptr_t symDomainGet) {
    return getter_uses_bl(pid, symDomainGet);
}

bool remote_il2cpp_session_call_domain_get(RemoteSession &s, pid_t pid, uintptr_t symDomainGet,
                                           uintptr_t &domainOut) {
    domainOut = 0;
    if (!symDomainGet) return false;
    std::vector<uintptr_t> targets;
    const bool blWrap = getter_uses_bl(pid, symDomainGet);
    if (!blWrap) targets.push_back(symDomainGet);
    uint32_t ins[24] = {};
    if (mem_read(pid, symDomainGet, ins, sizeof(ins))) {
        for (int i = 0; i < 20; ++i) {
            const uint64_t pc = symDomainGet + (uint64_t)i * 4;
            const uintptr_t blt = decode_bl_target(ins[i], pc);
            if (blt) targets.push_back(blt);
        }
    }
    int tried = 0;
    for (uintptr_t fn : targets) {
        if (!fn) continue;
        if (tried++ > 6) break;
        uintptr_t d = 0;
        if (remote_session_call(s, fn, {}, d) && domain_looks_valid(pid, d)) {
            domainOut = d;
            return true;
        }
    }
    return false;
}

bool remote_il2cpp_domain_valid(pid_t pid, uintptr_t domain) {
    if (!mem_ptr_ok(domain)) return false;
    uintptr_t words[16] = {};
    if (!mem_read(pid, domain, words, sizeof(words))) return false;
    int ptrLike = 0;
    for (uintptr_t w : words)
        if (mem_ptr_ok(w)) ptrLike++;
    return ptrLike >= 2;
}

static bool live_call_domain_get(pid_t pid, uintptr_t sym, uintptr_t &domainOut, char *err,
                                 size_t errCap) {
    domainOut = 0;
    RemoteSession s{};
    if (!remote_session_begin(pid, s)) {
        if (err && errCap) std::snprintf(err, errCap, "%s", s.err);
        return false;
    }
    const bool ok = remote_il2cpp_session_call_domain_get(s, pid, sym, domainOut);
    if (!ok && err && errCap) std::snprintf(err, errCap, "domain_get live call failed");
    remote_session_end(s);
    return ok;
}

bool remote_il2cpp_prime_domain(pid_t pid, RemoteIl2CppInfo &io) {
    if (!io.sym_domain_get) return false;
    uintptr_t domain = 0;
    char err[160] = {};
    if (!live_call_domain_get(pid, io.sym_domain_get, domain, err, sizeof(err))) return false;
    io.domain_ptr = domain;
    std::snprintf(io.note, sizeof(io.note), "live il2cpp_domain_get -> 0x%llx",
                  (unsigned long long)domain);
    return true;
}

bool remote_refresh_domain_ptr(pid_t pid, RemoteIl2CppInfo &io) {
    if (!io.sym_domain_get) return false;
    if (domain_from_getter(pid, io.sym_domain_get, io.domain_ptr)) {
        std::snprintf(io.note, sizeof(io.note), "domain* decoded @ 0x%llx",
                      (unsigned long long)io.domain_ptr);
        return true;
    }
    uint32_t ins[8] = {};
    mem_read(pid, io.sym_domain_get, ins, sizeof(ins));
    ui_log("[il2cpp] domain_get ins: %08X %08X %08X %08X", ins[0], ins[1], ins[2], ins[3]);
    if (getter_uses_bl(pid, io.sym_domain_get)) {
        std::snprintf(io.note, sizeof(io.note), "domain_get uses BL — use GOT decode / live call");
        return false;
    }
    domain_scan_bss(pid, io, io.domain_ptr);
    if (io.domain_ptr && domain_looks_valid(pid, io.domain_ptr)) {
        std::snprintf(io.note, sizeof(io.note), "domain* bss scan @ 0x%llx",
                      (unsigned long long)io.domain_ptr);
        return true;
    }
    io.domain_ptr = 0;
    return false;
}

void remote_il2cpp_invalidate_cache(pid_t pid) {
    if (g_il2CachedPid == pid) {
        g_il2CachedPid = 0;
        g_il2Cached = RemoteIl2CppInfo{};
    }
}

bool remote_detect_il2cpp(pid_t pid, RemoteIl2CppInfo &out) {
    if (g_il2CachedPid == pid && g_il2Cached.sym_domain_get) {
        out = g_il2Cached;
        if (!out.domain_ptr || !domain_looks_valid(pid, out.domain_ptr))
            remote_refresh_domain_ptr(pid, out);
        g_il2Cached = out;
        return true;
    }

    out = RemoteIl2CppInfo{};
    std::vector<SoModule> mods;
    collect_modules(pid, mods);
    if (mods.empty()) {
        std::snprintf(out.note, sizeof(out.note), "no mappable .so in pid %d", (int)pid);
        return false;
    }

    int tried = 0;
    for (const SoModule &m : mods) {
        if (!module_like_il2cpp(m)) continue;
        ++tried;
        int hits = 0;
        if (try_module(pid, m, out, hits)) {
            if (!out.domain_ptr || !domain_looks_valid(pid, out.domain_ptr))
                remote_refresh_domain_ptr(pid, out);
            g_il2CachedPid = pid;
            g_il2Cached = out;
            ui_log("[il2cpp] OK lib=%s base=0x%llx domain_get=0x%llx apis=%d",
                   out.libBaseName, (unsigned long long)out.base,
                   (unsigned long long)out.sym_domain_get, hits);
            ui_log("[il2cpp] %s", out.note);
            return true;
        }
    }

    for (const SoModule &m : mods) {
        ++tried;
        int hits = 0;
        if (try_module(pid, m, out, hits)) {
            if (!out.domain_ptr || !domain_looks_valid(pid, out.domain_ptr))
                remote_refresh_domain_ptr(pid, out);
            g_il2CachedPid = pid;
            g_il2Cached = out;
            ui_log("[il2cpp] OK (fallback) lib=%s apis=%d", out.libBaseName, hits);
            return true;
        }
    }

    std::snprintf(out.note, sizeof(out.note),
                  "scanned %zu modules (%d tried), no il2cpp_domain_get in dynsym/symtab",
                  mods.size(), tried);
    ui_log("[il2cpp] FAIL %s", out.note);
    if (!mods.empty())
        ui_log("[il2cpp] top map: %s @ 0x%llx", mods[0].path.c_str(),
               (unsigned long long)mods[0].base);
    return false;
}
