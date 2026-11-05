#include "il2cpp_remote.hpp"
#include "mem.hpp"
#include "remote_elf.hpp"
#include <cstring>
#include <functional>
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

static bool resolve_sym(pid_t pid, const SoModule &m, const char *sym, uintptr_t &addr) {
    addr = 0;
    if (elf_remote_sym(pid, m.base, sym, addr)) return true;
    ElfRemote er{};
    if (!elf_remote_bias(pid, m.base, er)) return false;
    return elf_file_sym(m.path.c_str(), er.load_bias, sym, addr);
}

static const char *kDumpSyms[] = {
    "il2cpp_domain_get",
    "il2cpp_thread_attach",
    "il2cpp_domain_get_assemblies",
    "il2cpp_assembly_get_image",
    "il2cpp_image_get_name",
    "il2cpp_image_get_class_count",
    "il2cpp_image_get_class",
    "il2cpp_class_get_type",
    "il2cpp_class_from_type",
    "il2cpp_class_get_namespace",
    "il2cpp_class_get_flags",
    "il2cpp_class_is_valuetype",
    "il2cpp_class_is_enum",
    "il2cpp_class_get_parent",
    "il2cpp_class_get_interfaces",
    "il2cpp_class_instance_size",
    "il2cpp_class_get_methods",
    "il2cpp_class_get_properties",
    "il2cpp_class_get_fields",
    "il2cpp_method_get_flags",
    "il2cpp_method_get_return_type",
    "il2cpp_type_is_byref",
    "il2cpp_method_get_name",
    "il2cpp_method_get_param_count",
    "il2cpp_method_get_param",
    "il2cpp_method_get_param_name",
    "il2cpp_class_get_name",
    "il2cpp_class_get_element_class",
    "il2cpp_class_get_rank",
    "il2cpp_property_get_get_method",
    "il2cpp_property_get_set_method",
    "il2cpp_property_get_name",
    "il2cpp_field_get_flags",
    "il2cpp_field_get_type",
    "il2cpp_field_get_name",
    "il2cpp_field_static_get_value",
    "il2cpp_field_get_offset",
};

} // namespace

uintptr_t RemoteIl2CppExecutor::scratch(size_t bytes) {
    if (!sessionOpen_) return 0;
    const uintptr_t p = remote_session_scratch(session_, scratchSlot_++, bytes);
    if (p) {
        uint64_t z = 0;
        mem_write(pid, p, &z, std::min(bytes, sizeof(z)));
    }
    return p;
}

uintptr_t RemoteIl2CppExecutor::sym(const char *name) const {
    auto it = sym_.find(name);
    return it == sym_.end() ? 0 : it->second;
}

bool RemoteIl2CppExecutor::call0(const char *name, uintptr_t &ret) {
    const uintptr_t fn = sym(name);
    if (!fn) return false;
    return remote_session_call(session_, fn, {}, ret);
}

bool RemoteIl2CppExecutor::call1(const char *name, uintptr_t a0, uintptr_t &ret) {
    const uintptr_t fn = sym(name);
    if (!fn) return false;
    return remote_session_call(session_, fn, {a0}, ret);
}

bool RemoteIl2CppExecutor::call2(const char *name, uintptr_t a0, uintptr_t a1, uintptr_t &ret) {
    const uintptr_t fn = sym(name);
    if (!fn) return false;
    return remote_session_call(session_, fn, {a0, a1}, ret);
}

bool RemoteIl2CppExecutor::call2_out(const char *name, uintptr_t a0, uintptr_t outRemote,
                                     uintptr_t &ret) {
    return call2(name, a0, outRemote, ret);
}

bool RemoteIl2CppExecutor::read_cstr(uintptr_t remote, std::string &out) {
    out.clear();
    if (!mem_ptr_ok(remote)) return false;
    char buf[512];
    if (!mem_read(pid, remote, buf, sizeof(buf) - 1)) return false;
    buf[sizeof(buf) - 1] = 0;
    out.assign(buf);
    return true;
}

bool RemoteIl2CppExecutor::resolve_syms(char *err, size_t errCap) {
    sym_.clear();
    SoModule mod{info.libPath, info.base, info.end};
    for (const char *s : kDumpSyms) {
        uintptr_t a = 0;
        if (!resolve_sym(pid, mod, s, a)) {
            if (std::strcmp(s, "il2cpp_thread_attach") == 0 || std::strcmp(s, "il2cpp_type_is_byref") == 0)
                continue;
            std::snprintf(err, errCap, "missing symbol %s", s);
            return false;
        }
        sym_[s] = a;
    }
    if (info.sym_domain_get) sym_["il2cpp_domain_get"] = info.sym_domain_get;
    return sym_.count("il2cpp_domain_get") > 0;
}

bool RemoteIl2CppExecutor::open(pid_t target, char *err, size_t errCap) {
    close();
    pid = target;
    if (!remote_detect_il2cpp(pid, info)) {
        std::snprintf(err, errCap, "no IL2CPP module (il2cpp_domain_get export)");
        return false;
    }
    if (!remote_il2cpp_prime_domain(pid, info) && !info.domain_ptr) {
        remote_refresh_domain_ptr(pid, info);
    }
    if (!remote_session_begin(pid, session_)) {
        std::snprintf(err, errCap, "%s", session_.err);
        return false;
    }
    sessionOpen_ = true;
    scratchSlot_ = 0;
    if (!resolve_syms(err, errCap)) {
        close();
        return false;
    }
    return true;
}

void RemoteIl2CppExecutor::close() {
    if (sessionOpen_) {
        remote_session_end(session_);
        sessionOpen_ = false;
    }
    scratchSlot_ = 0;
    sym_.clear();
}

bool RemoteIl2CppExecutor::run_dump(const std::string &outPath, const std::string &targetCmdline,
                                      DumpLogFn log, DumpProgressFn progress) {
    DumpCtx ctx{};
    ctx.pid = pid;
    ctx.il2cppBase = info.base;
    ctx.il2cppEnd = info.end;
    ctx.libName = info.libBaseName[0] ? info.libBaseName : basename(info.libPath);
    ctx.sym = [this](const char *n) { return sym(n); };
    ctx.call0 = [this](const char *n, uintptr_t &r) { return call0(n, r); };
    ctx.call1 = [this](const char *n, uintptr_t a0, uintptr_t &r) { return call1(n, a0, r); };
    ctx.call2 = [this](const char *n, uintptr_t a0, uintptr_t a1, uintptr_t &r) {
        return call2(n, a0, a1, r);
    };
    ctx.scratch = [this](size_t b) { return scratch(b); };
    ctx.readCstr = [this](uintptr_t remote, std::string &o) { return read_cstr(remote, o); };
    ctx.readMem = [this](uintptr_t remote, void *buf, size_t n) {
        return mem_read(pid, remote, buf, n);
    };
    return dump_cs_run(ctx, outPath, targetCmdline, log, progress);
}
