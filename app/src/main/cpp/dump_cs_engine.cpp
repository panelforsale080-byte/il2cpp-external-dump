#include "dump_cs_engine.hpp"
#include "Il2cpp/il2cpp-tabledefs.h"
#include "Il2cpp/il2cpp_types_minimal.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>

namespace {

struct SoMap {
    uint64_t start = 0, end = 0, fileOff = 0;
    bool exec = false;
    std::string name;
};

static std::vector<SoMap> g_maps;

static void refresh_maps(DumpCtx &ctx) {
    g_maps.clear();
    char path[64];
    std::snprintf(path, sizeof(path), "/proc/%d/maps", (int)ctx.pid);
    FILE *maps = std::fopen(path, "r");
    if (!maps) return;
    char line[1024];
    while (std::fgets(line, sizeof(line), maps)) {
        SoMap map;
        char perms[8] = {};
        if (std::sscanf(line, "%lx-%lx %7s %lx", &map.start, &map.end, perms, &map.fileOff) != 4)
            continue;
        map.exec = std::strchr(perms, 'x') != nullptr;
        const char *p = std::strchr(line, '/');
        if (p) {
            std::string full(p);
            while (!full.empty() && (full.back() == '\n' || full.back() == '\r' || full.back() == ' '))
                full.pop_back();
            const auto slash = full.find_last_of('/');
            map.name = (slash == std::string::npos) ? full : full.substr(slash + 1);
        }
        g_maps.push_back(map);
    }
    std::fclose(maps);
}

static bool find_map(uint64_t addr, SoMap &out) {
    const SoMap *best = nullptr;
    for (const auto &m : g_maps) {
        if (addr < m.start || addr >= m.end) continue;
        if (!best || (m.exec && !best->exec)) best = &m;
    }
    if (!best) return false;
    out = *best;
    return true;
}

static void method_offset_info(DumpCtx &ctx, uint64_t addr, uint64_t &offset, uint64_t &moduleRva,
                               std::string &libName) {
    offset = moduleRva = 0;
    libName = ctx.libName;
    SoMap map;
    if (addr && find_map(addr, map)) {
        moduleRva = (addr - map.start) + map.fileOff;
        const uint64_t bias = map.start - map.fileOff;
        offset = (addr >= bias) ? (addr - bias) : moduleRva;
        if (!map.name.empty()) libName = map.name;
        return;
    }
    if (addr && ctx.il2cppBase && addr >= ctx.il2cppBase)
        offset = moduleRva = addr - ctx.il2cppBase;
}

static bool read_type(DumpCtx &ctx, uintptr_t remote, Il2CppType &out) {
    return ctx.readMem(remote, &out, sizeof(out));
}

static bool type_is_byref(DumpCtx &ctx, uintptr_t remoteType) {
    Il2CppType t{};
    if (!read_type(ctx, remoteType, t)) return false;
    uintptr_t ret = 0;
    if (ctx.call1("il2cpp_type_is_byref", remoteType, ret))
        return ret != 0;
    return t.byref != 0;
}

static std::string method_modifier(uint32_t flags) {
    std::stringstream o;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
    case METHOD_ATTRIBUTE_PRIVATE: o << "private "; break;
    case METHOD_ATTRIBUTE_PUBLIC: o << "public "; break;
    case METHOD_ATTRIBUTE_FAMILY: o << "protected "; break;
    case METHOD_ATTRIBUTE_ASSEM:
    case METHOD_ATTRIBUTE_FAM_AND_ASSEM: o << "internal "; break;
    case METHOD_ATTRIBUTE_FAM_OR_ASSEM: o << "protected internal "; break;
    default: break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) o << "static ";
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        o << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) o << "override ";
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) o << "sealed override ";
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) o << "virtual ";
        else o << "override ";
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) o << "extern ";
    return o.str();
}

static std::string cs_type_name(DumpCtx &ctx, uintptr_t klass);

static std::string cs_type_name_from_type(DumpCtx &ctx, uintptr_t remoteType) {
    if (!remoteType) return "void";
    Il2CppType t{};
    if (!read_type(ctx, remoteType, t)) return "void";
    uintptr_t klass = 0;
    if (!ctx.call1("il2cpp_class_from_type", remoteType, klass)) return "void";
    return cs_type_name(ctx, klass);
}

static std::string cs_type_name(DumpCtx &ctx, uintptr_t klass) {
    if (!klass) return "void";
    uintptr_t remoteType = 0;
    if (ctx.call1("il2cpp_class_get_type", klass, remoteType) && remoteType) {
        Il2CppType t{};
        if (read_type(ctx, remoteType, t)) {
            switch (t.type) {
            case IL2CPP_TYPE_SZARRAY: {
                uintptr_t el = 0;
                ctx.call1("il2cpp_class_get_element_class", klass, el);
                return cs_type_name(ctx, el) + "[]";
            }
            case IL2CPP_TYPE_ARRAY: {
                uintptr_t el = 0;
                ctx.call1("il2cpp_class_get_element_class", klass, el);
                int rank = 0;
                uintptr_t r = 0;
                if (ctx.call1("il2cpp_class_get_rank", klass, r)) rank = (int)r;
                std::string rs = "[";
                for (int i = 1; i < rank; ++i) rs += ",";
                rs += "]";
                return cs_type_name(ctx, el) + rs;
            }
            case IL2CPP_TYPE_PTR: {
                uintptr_t el = 0;
                ctx.call1("il2cpp_class_get_element_class", klass, el);
                return cs_type_name(ctx, el) + "*";
            }
            default: break;
            }
        }
    }
    std::string name;
    uintptr_t namePtr = 0;
    if (!ctx.call1("il2cpp_class_get_name", klass, namePtr) || !ctx.readCstr(namePtr, name))
        return "unknown";
    if (name == "Single") return "float";
    if (name == "Int32") return "int";
    if (name == "Int64") return "long";
    if (name == "Boolean") return "bool";
    if (name == "String") return "string";
    if (name == "Void") return "void";
    if (name == "Object") return "object";
    if (name == "Byte") return "byte";
    if (name == "UInt32") return "uint";
    if (name == "Double") return "double";
    return name;
}

static std::string method_signature(DumpCtx &ctx, uintptr_t method) {
    std::stringstream out;
    uintptr_t iflagsSlot = ctx.scratch(8);
    uintptr_t flagsRet = 0;
    ctx.call2("il2cpp_method_get_flags", method, iflagsSlot, flagsRet);
    uint32_t iflags = 0;
    ctx.readMem(iflagsSlot, &iflags, sizeof(iflags));
    out << method_modifier((uint32_t)flagsRet);

    uintptr_t retType = 0;
    ctx.call1("il2cpp_method_get_return_type", method, retType);
    if (type_is_byref(ctx, retType)) out << "ref ";
    out << cs_type_name_from_type(ctx, retType) << " ";

    uintptr_t namePtr = 0;
    std::string mname;
    if (ctx.call1("il2cpp_method_get_name", method, namePtr)) ctx.readCstr(namePtr, mname);
    out << mname << "(";

    uintptr_t paramCount = 0;
    ctx.call1("il2cpp_method_get_param_count", method, paramCount);
    for (uintptr_t i = 0; i < paramCount; ++i) {
        uintptr_t param = 0;
        ctx.call2("il2cpp_method_get_param", method, i, param);
        Il2CppType pt{};
        read_type(ctx, param, pt);
        if (type_is_byref(ctx, param)) {
            if ((pt.attrs & PARAM_ATTRIBUTE_OUT) && !(pt.attrs & PARAM_ATTRIBUTE_IN)) out << "out ";
            else if ((pt.attrs & PARAM_ATTRIBUTE_IN) && !(pt.attrs & PARAM_ATTRIBUTE_OUT)) out << "in ";
            else out << "ref ";
        }
        out << cs_type_name_from_type(ctx, param) << " ";
        uintptr_t pn = 0;
        std::string pns;
        if (ctx.call2("il2cpp_method_get_param_name", method, i, pn) && ctx.readCstr(pn, pns))
            out << pns;
        else
            out << "param" << i;
        out << ", ";
    }
    if (paramCount > 0) {
        auto s = out.str();
        if (s.size() >= 2) out.str(s.substr(0, s.size() - 2));
    }
    out << ")";
    return out.str();
}

static std::string dump_methods(DumpCtx &ctx, uintptr_t klass) {
    std::stringstream out;
    out << "\n\t// Methods";
    uintptr_t iter = ctx.scratch(8);
    uint64_t zero = 0;
    ctx.readMem(iter, &zero, 0); // scratch zeroed by allocator
    for (;;) {
        uintptr_t method = 0;
        if (!ctx.call2("il2cpp_class_get_methods", klass, iter, method) || !method) break;
        uint64_t absAddr = 0;
        ctx.readMem(method, &absAddr, sizeof(absAddr));
        uint64_t offset = 0, rva = 0;
        std::string lib;
        method_offset_info(ctx, absAddr, offset, rva, lib);
        out << "\n\t// Offset: 0x" << std::hex << offset;
        out << "\n\t// ModuleRVA: 0x" << rva;
        out << "\n\t// Address: 0x" << absAddr;
        if (!lib.empty()) out << "\n\t// Lib: " << lib;
        out << "\n\t" << method_signature(ctx, method) << " { }\n";
    }
    return out.str();
}

static std::string dump_properties(DumpCtx &ctx, uintptr_t klass) {
    std::stringstream out;
    out << "\n\t// Properties\n";
    uintptr_t iter = ctx.scratch(8);
    for (;;) {
        uintptr_t prop = 0;
        if (!ctx.call2("il2cpp_class_get_properties", klass, iter, prop) || !prop) break;
        uintptr_t get = 0, set = 0, namePtr = 0;
        ctx.call1("il2cpp_property_get_get_method", prop, get);
        ctx.call1("il2cpp_property_get_set_method", prop, set);
        ctx.call1("il2cpp_property_get_name", prop, namePtr);
        std::string pname;
        ctx.readCstr(namePtr, pname);
        out << "\t";
        uintptr_t propKlass = 0;
        if (get) {
            uintptr_t iflagsSlot = ctx.scratch(8);
            uintptr_t flagsRet = 0;
            ctx.call2("il2cpp_method_get_flags", get, iflagsSlot, flagsRet);
            out << method_modifier((uint32_t)flagsRet);
            uintptr_t rt = 0;
            ctx.call1("il2cpp_method_get_return_type", get, rt);
            propKlass = 0;
            ctx.call1("il2cpp_class_from_type", rt, propKlass);
        } else if (set) {
            uintptr_t iflagsSlot = ctx.scratch(8);
            uintptr_t flagsRet = 0;
            ctx.call2("il2cpp_method_get_flags", set, iflagsSlot, flagsRet);
            out << method_modifier((uint32_t)flagsRet);
            uintptr_t param = 0;
            ctx.call2("il2cpp_method_get_param", set, (uintptr_t)0, param);
            ctx.call1("il2cpp_class_from_type", param, propKlass);
        }
        if (propKlass)
            out << cs_type_name(ctx, propKlass) << " " << pname << " { "
                << (get ? "get; " : "") << (set ? "set; " : "") << "}\n";
    }
    return out.str();
}

static std::string dump_fields(DumpCtx &ctx, uintptr_t klass) {
    std::stringstream out;
    out << "\n\t// Fields\n";
    uintptr_t isEnum = 0;
    ctx.call1("il2cpp_class_is_enum", klass, isEnum);
    uintptr_t iter = ctx.scratch(8);
    for (;;) {
        uintptr_t field = 0;
        if (!ctx.call2("il2cpp_class_get_fields", klass, iter, field) || !field) break;
        uintptr_t attrs = 0;
        ctx.call1("il2cpp_field_get_flags", field, attrs);
        auto access = (uint32_t)attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
        case FIELD_ATTRIBUTE_PRIVATE: out << "\tprivate "; break;
        case FIELD_ATTRIBUTE_PUBLIC: out << "\tpublic "; break;
        case FIELD_ATTRIBUTE_FAMILY: out << "\tprotected "; break;
        case FIELD_ATTRIBUTE_ASSEMBLY:
        case FIELD_ATTRIBUTE_FAM_AND_ASSEM: out << "\tinternal "; break;
        case FIELD_ATTRIBUTE_FAM_OR_ASSEM: out << "\tprotected internal "; break;
        default: out << "\t"; break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) out << "const ";
        else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) out << "static ";
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) out << "readonly ";
        }
        uintptr_t ftype = 0;
        ctx.call1("il2cpp_field_get_type", field, ftype);
        uintptr_t fklass = 0;
        ctx.call1("il2cpp_class_from_type", ftype, fklass);
        uintptr_t fnamePtr = 0;
        std::string fname;
        ctx.call1("il2cpp_field_get_name", field, fnamePtr);
        ctx.readCstr(fnamePtr, fname);
        out << cs_type_name(ctx, fklass) << " " << fname;
        if ((attrs & FIELD_ATTRIBUTE_LITERAL) && isEnum) {
            uintptr_t valSlot = ctx.scratch(8);
            uintptr_t ignored = 0;
            ctx.call2("il2cpp_field_static_get_value", field, valSlot, ignored);
            uint64_t val = 0;
            ctx.readMem(valSlot, &val, sizeof(val));
            out << " = " << std::dec << val;
        }
        uintptr_t off = 0;
        ctx.call1("il2cpp_field_get_offset", field, off);
        out << "; // Offset: 0x" << std::hex << off;
        if (attrs & FIELD_ATTRIBUTE_STATIC) out << " static";
        if (!ctx.libName.empty()) out << " Lib: " << ctx.libName;
        out << "\n";
    }
    return out.str();
}

static std::string dump_type_cs(DumpCtx &ctx, uintptr_t remoteType) {
    std::stringstream out;
    if (!remoteType) return "\n// skipped invalid type\n";
    uintptr_t klass = 0;
    if (!ctx.call1("il2cpp_class_from_type", remoteType, klass) || !klass)
        return "\n// skipped null class\n";

    uintptr_t nsPtr = 0;
    std::string ns;
    ctx.call1("il2cpp_class_get_namespace", klass, nsPtr);
    ctx.readCstr(nsPtr, ns);
    out << "\n// Namespace: " << ns << "\n";

    uintptr_t flags = 0;
    ctx.call1("il2cpp_class_get_flags", klass, flags);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) out << "[Serializable]\n";

    uintptr_t isVt = 0, isEn = 0;
    ctx.call1("il2cpp_class_is_valuetype", klass, isVt);
    ctx.call1("il2cpp_class_is_enum", klass, isEn);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
    case TYPE_ATTRIBUTE_PUBLIC:
    case TYPE_ATTRIBUTE_NESTED_PUBLIC: out << "public "; break;
    case TYPE_ATTRIBUTE_NOT_PUBLIC:
    case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
    case TYPE_ATTRIBUTE_NESTED_ASSEMBLY: out << "internal "; break;
    case TYPE_ATTRIBUTE_NESTED_PRIVATE: out << "private "; break;
    case TYPE_ATTRIBUTE_NESTED_FAMILY: out << "protected "; break;
    case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM: out << "protected internal "; break;
    default: break;
    }
    if ((flags & TYPE_ATTRIBUTE_ABSTRACT) && (flags & TYPE_ATTRIBUTE_SEALED))
        out << "static ";
    else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && (flags & TYPE_ATTRIBUTE_ABSTRACT))
        out << "abstract ";
    else if (!isVt && !isEn && (flags & TYPE_ATTRIBUTE_SEALED))
        out << "sealed ";
    if (flags & TYPE_ATTRIBUTE_INTERFACE)
        out << "interface ";
    else if (isEn)
        out << "enum ";
    else if (isVt)
        out << "struct ";
    else
        out << "class ";
    out << cs_type_name(ctx, klass);

    std::vector<std::string> extends;
    uintptr_t parent = 0;
    ctx.call1("il2cpp_class_get_parent", klass, parent);
    if (!isVt && !isEn && parent) {
        uintptr_t pt = 0;
        ctx.call1("il2cpp_class_get_type", parent, pt);
        Il2CppType pty{};
        read_type(ctx, pt, pty);
        if (pty.type != IL2CPP_TYPE_OBJECT) extends.push_back(cs_type_name(ctx, parent));
    }
    uintptr_t itIter = ctx.scratch(8);
    for (;;) {
        uintptr_t itf = 0;
        if (!ctx.call2("il2cpp_class_get_interfaces", klass, itIter, itf) || !itf) break;
        extends.push_back(cs_type_name(ctx, itf));
    }
    if (!extends.empty()) {
        out << " : " << extends[0];
        for (size_t i = 1; i < extends.size(); ++i) out << ", " << extends[i];
    }
    uintptr_t instSize = 0;
    ctx.call1("il2cpp_class_instance_size", klass, instSize);
    out << "\n// InstanceSize: 0x" << std::hex << instSize << std::dec << "\n{";
    out << dump_fields(ctx, klass);
    out << dump_properties(ctx, klass);
    out << dump_methods(ctx, klass);
    out << "\n}\n";
    return out.str();
}

} // namespace

bool dump_cs_run(DumpCtx &ctx, const std::string &outPath, const std::string &targetLabel,
                 DumpLogFn log, DumpProgressFn progressFn) {
    if (!ctx.call0 || !ctx.sym) return false;
    refresh_maps(ctx);

    auto logf = [&](const char *fmt, ...) {
        char buf[1024];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (log) log(buf);
    };

    if (!ctx.sym("il2cpp_domain_get") || !ctx.sym("il2cpp_domain_get_assemblies")) {
        logf("ERROR: missing domain APIs");
        return false;
    }

    uintptr_t domain = 0;
    if (!ctx.call0("il2cpp_domain_get", domain) || !domain) {
        logf("ERROR: il2cpp_domain_get returned null");
        return false;
    }
    logf("domain=0x%llx", (unsigned long long)domain);

    if (ctx.sym("il2cpp_thread_attach"))
        ctx.call1("il2cpp_thread_attach", domain, domain);

    uintptr_t sizeSlot = ctx.scratch(8);
    uintptr_t assemblies = 0;
    if (!ctx.call2("il2cpp_domain_get_assemblies", domain, sizeSlot, assemblies) || !assemblies) {
        logf("ERROR: no assemblies");
        return false;
    }
    size_t asmCount = 0;
    ctx.readMem(sizeSlot, &asmCount, sizeof(asmCount));
    logf("assemblies=%zu", asmCount);

    std::ofstream out(outPath, std::ios::trunc);
    if (!out.is_open()) {
        logf("ERROR: cannot open %s", outPath.c_str());
        return false;
    }

    out << "// IL2CPP Dumped (external / conRent-style)\n";
    out << "// Target: " << targetLabel << "\n";
    out << "// Library: " << ctx.libName << "\n";
    out << "// Base: 0x" << std::hex << ctx.il2cppBase << std::dec << "\n\n";

    int totalClasses = 0;
    if (ctx.sym("il2cpp_image_get_class")) {
        for (size_t i = 0; i < asmCount; ++i) {
            uintptr_t asmPtr = 0;
            ctx.readMem(assemblies + i * sizeof(uintptr_t), &asmPtr, sizeof(asmPtr));
            uintptr_t image = 0;
            ctx.call1("il2cpp_assembly_get_image", asmPtr, image);
            if (!image) continue;
            uintptr_t cc = 0;
            ctx.call1("il2cpp_image_get_class_count", image, cc);
            totalClasses += (int)cc;
        }
    }
    logf("classes=%d writing %s", totalClasses, outPath.c_str());

    int processed = 0;
    for (size_t i = 0; i < asmCount; ++i) {
        uintptr_t asmPtr = 0;
        ctx.readMem(assemblies + i * sizeof(uintptr_t), &asmPtr, sizeof(asmPtr));
        uintptr_t image = 0;
        ctx.call1("il2cpp_assembly_get_image", asmPtr, image);
        if (!image) continue;
        uintptr_t namePtr = 0;
        std::string imageName;
        if (ctx.call1("il2cpp_image_get_name", image, namePtr)) ctx.readCstr(namePtr, imageName);
        out << "// Image " << i << ": " << imageName << "\n";

        uintptr_t classCount = 0;
        ctx.call1("il2cpp_image_get_class_count", image, classCount);
        logf("image %zu/%zu %s classes=%llu", i + 1, asmCount, imageName.c_str(),
             (unsigned long long)classCount);

        DumpProgress pr{};
        pr.totalClasses = totalClasses;
        pr.currentClass = processed;
        pr.progress = totalClasses > 0 ? (float)processed / (float)totalClasses : 0.f;
        std::snprintf(pr.imageName, sizeof(pr.imageName), "%s", imageName.c_str());
        if (progressFn) progressFn(pr);

        for (uintptr_t j = 0; j < classCount; ++j) {
            uintptr_t klass = 0;
            ctx.call2("il2cpp_image_get_class", image, j, klass);
            if (!klass) {
                ++processed;
                continue;
            }
            uintptr_t type = 0;
            ctx.call1("il2cpp_class_get_type", klass, type);
            out << dump_type_cs(ctx, type);
            ++processed;
            if ((processed % 200) == 0) out.flush();
        }
        out.flush();
    }
    out.close();
    logf("SUCCESS dump.cs classes=%d path=%s", processed, outPath.c_str());
    DumpProgress done{};
    done.progress = 1.f;
    done.totalClasses = totalClasses;
    done.currentClass = processed;
    if (progressFn) progressFn(done);
    return true;
}
