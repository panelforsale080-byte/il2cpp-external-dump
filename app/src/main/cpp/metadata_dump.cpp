#include "metadata_dump.hpp"
#include "mem.hpp"
#include "ui_log.hpp"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kMetaSanity = 0xFAB11BAF;

#pragma pack(push, 1)
struct MetaHeader {
    int32_t sanity;
    int32_t version;
    int32_t stringLiteralOffset;
    int32_t stringLiteralCount;
    int32_t stringLiteralDataOffset;
    int32_t stringLiteralDataCount;
    int32_t stringOffset;
    int32_t stringCount;
    int32_t eventsOffset;
    int32_t eventsCount;
    int32_t propertiesOffset;
    int32_t propertiesCount;
    int32_t methodsOffset;
    int32_t methodsCount;
    int32_t parameterDefaultValuesOffset;
    int32_t parameterDefaultValuesCount;
    int32_t fieldDefaultValuesOffset;
    int32_t fieldDefaultValuesCount;
    int32_t fieldAndParameterDefaultValueDataOffset;
    int32_t fieldAndParameterDefaultValueDataCount;
    int32_t fieldMarshaledSizesOffset;
    int32_t fieldMarshaledSizesCount;
    int32_t parametersOffset;
    int32_t parametersCount;
    int32_t fieldsOffset;
    int32_t fieldsCount;
    int32_t genericParametersOffset;
    int32_t genericParametersCount;
    int32_t genericParameterConstraintsOffset;
    int32_t genericParameterConstraintsCount;
    int32_t genericContainersOffset;
    int32_t genericContainersCount;
    int32_t nestedTypesOffset;
    int32_t nestedTypesCount;
    int32_t interfacesOffset;
    int32_t interfacesCount;
    int32_t vtableMethodsOffset;
    int32_t vtableMethodsCount;
    int32_t interfaceOffsetsOffset;
    int32_t interfaceOffsetsCount;
    int32_t typeDefinitionsOffset;
    int32_t typeDefinitionsCount;
    int32_t imagesOffset;
    int32_t imagesCount;
    int32_t assembliesOffset;
    int32_t assembliesCount;
    int32_t metadataUsageListsOffset;
    int32_t metadataUsageListsCount;
    int32_t metadataUsagePairsOffset;
    int32_t metadataUsagePairsCount;
    int32_t fieldRefsOffset;
    int32_t fieldRefsCount;
    int32_t referencedAssembliesOffset;
    int32_t referencedAssembliesCount;
    int32_t attributesInfoOffset;
    int32_t attributesInfoCount;
    int32_t attributeTypesOffset;
    int32_t attributeTypesCount;
    int32_t typesOffset;
    int32_t typesCount;
};
#pragma pack(pop)

struct TypeDef {
    int32_t nameIndex;
    int32_t namespaceIndex;
    int32_t byvalTypeIndex;
    int32_t byrefTypeIndex;
    int32_t declaringTypeIndex;
    int32_t parentIndex;
    int32_t elementTypeIndex;
    int32_t genericContainerIndex;
    uint32_t flags;
    int32_t fieldStart;
    int32_t methodStart;
    int32_t eventStart;
    int32_t propertyStart;
    int32_t nestedTypesStart;
    int32_t interfacesStart;
    int32_t vtableStart;
    int32_t interfaceOffsetsStart;
    uint16_t method_count;
    uint16_t property_count;
    uint16_t field_count;
    uint16_t event_count;
    uint16_t nested_type_count;
    uint16_t vtable_count;
    uint16_t interfaces_count;
    uint16_t interface_offsets_count;
    uint32_t bitfield;
    uint32_t token;
};

struct FieldDef {
    int32_t nameIndex;
    int32_t typeIndex;
    uint32_t token;
};

struct MethodDef {
    int32_t nameIndex;
    int32_t declaringType;
    int32_t returnType;
    int32_t parameterStart;
    int32_t genericContainerIndex;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};

struct ParamDef {
    int32_t nameIndex;
    uint32_t token;
    int32_t typeIndex;
};

struct ImageDef {
    int32_t nameIndex;
    int32_t assemblyIndex;
    int32_t typeStart;
    uint32_t typeCount;
};

struct MetaView {
    pid_t pid = 0;
    uintptr_t base = 0;
    MetaHeader hdr{};
    std::vector<uint8_t> blob;
};

static int64_t meta_now_ms() {
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static bool validate_meta_header(const MetaHeader &h) {
    if (h.sanity != (int32_t)kMetaSanity) return false;
    if (h.version < 16 || h.version > 39) return false;
    if (h.typeDefinitionsCount <= 0 || h.typeDefinitionsCount > 200000) return false;
    if (h.imagesCount < 0 || h.imagesCount > 4096) return false;
    return true;
}

static bool scan_bytes_for_header(const uint8_t *data, size_t len, size_t &offOut) {
    offOut = 0;
    if (len < sizeof(MetaHeader)) return false;
    const size_t step = 4096;
    for (size_t off = 0; off + sizeof(MetaHeader) <= len; off += step) {
        for (size_t i = off; i + sizeof(MetaHeader) <= len && i < off + step + 4096; i += 4) {
            MetaHeader h{};
            std::memcpy(&h, data + i, sizeof(h));
            if (!validate_meta_header(h)) continue;
            offOut = i;
            return true;
        }
    }
    return false;
}

static bool scan_region(pid_t pid, uintptr_t start, size_t len, uintptr_t &found) {
    if (len < sizeof(MetaHeader)) return false;
    constexpr size_t kMaxScan = 12 * 1024 * 1024;
    len = std::min(len, kMaxScan);
    const size_t step = 65536;
    std::vector<uint8_t> chunk(step + sizeof(MetaHeader));
    for (size_t off = 0; off + sizeof(MetaHeader) <= len; off += step) {
        const size_t readSz = std::min(chunk.size(), len - off);
        if (!mem_read(pid, start + off, chunk.data(), readSz)) continue;
        size_t rel = 0;
        if (scan_bytes_for_header(chunk.data(), readSz, rel)) {
            found = start + off + rel;
            return true;
        }
    }
    return false;
}

static bool scan_file_path(const char *path, uintptr_t &foundRemote, std::vector<uint8_t> &fileCopy) {
    foundRemote = 0;
    fileCopy.clear();
    FILE *f = std::fopen(path, "rb");
    if (!f) return false;
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    if (sz <= (long)sizeof(MetaHeader) || sz > 96 * 1024 * 1024) {
        std::fclose(f);
        return false;
    }
    std::fseek(f, 0, SEEK_SET);
    fileCopy.resize((size_t)sz);
    if (std::fread(fileCopy.data(), 1, fileCopy.size(), f) != fileCopy.size()) {
        std::fclose(f);
        fileCopy.clear();
        return false;
    }
    std::fclose(f);
    size_t off = 0;
    if (!scan_bytes_for_header(fileCopy.data(), fileCopy.size(), off)) {
        fileCopy.clear();
        return false;
    }
    foundRemote = off;
    return true;
}

static std::vector<uint8_t> g_meta_file_cache;
static size_t g_meta_file_header_off = 0;

static bool load_metadata_from_map(pid_t pid, const MapsReg &m, uintptr_t &metaRemote) {
    const size_t len = std::min((size_t)(m.end - m.start), size_t(48 * 1024 * 1024));
    g_meta_file_cache.assign(len, 0);
    if (!mem_read(pid, m.start, g_meta_file_cache.data(), len)) {
        ui_log("[metadata] mem_read failed map=0x%llx len=%zu", (unsigned long long)m.start, len);
        return false;
    }
    size_t off = 0;
    if (!scan_bytes_for_header(g_meta_file_cache.data(), len, off)) {
        int32_t sanity = 0;
        std::memcpy(&sanity, g_meta_file_cache.data(), 4);
        ui_log("[metadata] no header in map (magic=%08x len=%zu)", (unsigned) sanity, len);
        g_meta_file_cache.clear();
        return false;
    }
    g_meta_file_header_off = off;
    metaRemote = m.start + off;
    MetaHeader hdr{};
    std::memcpy(&hdr, g_meta_file_cache.data() + off, sizeof(hdr));
    ui_log("[metadata] loaded from map +0x%zx v=%d types=%d", off, hdr.version,
           hdr.typeDefinitionsCount);
    return true;
}

static bool load_meta_view(pid_t pid, uintptr_t remote, MetaView &out);

static bool load_meta_view_cached(MetaView &v, pid_t pid, uintptr_t metaRemote) {
    if (!g_meta_file_cache.empty()) {
        v.pid = pid;
        v.base = metaRemote;
        if (g_meta_file_header_off + sizeof(MetaHeader) > g_meta_file_cache.size()) return false;
        std::memcpy(&v.hdr, g_meta_file_cache.data() + g_meta_file_header_off, sizeof(v.hdr));
        v.blob.assign(g_meta_file_cache.begin() + g_meta_file_header_off, g_meta_file_cache.end());
        return true;
    }
    return load_meta_view(pid, metaRemote, v);
}

static std::string read_meta_string(const MetaView &v, int32_t index) {
    if (index < 0 || index >= v.hdr.stringCount) return {};
    const int32_t off = v.hdr.stringOffset + index;
    if (off < 0 || (size_t)off >= v.blob.size()) return {};
    std::string s;
    for (size_t i = (size_t)off; i < v.blob.size(); ++i) {
        const char c = (char)v.blob[i];
        if (!c) break;
        s.push_back(c);
    }
    return s;
}

#pragma pack(push, 1)
struct Il2CppTypeRemote {
    int32_t dataIndex;
    uint16_t attrs;
    uint8_t type;
    uint8_t mods;
};
#pragma pack(pop)

static std::string type_def_name(const MetaView &v, int32_t typeDefIndex) {
    if (typeDefIndex < 0 || typeDefIndex >= v.hdr.typeDefinitionsCount) return "object";
    const size_t tdOff = (size_t)v.hdr.typeDefinitionsOffset + (size_t)typeDefIndex * sizeof(TypeDef);
    if (tdOff + sizeof(TypeDef) > v.blob.size()) return "object";
    TypeDef td{};
    std::memcpy(&td, v.blob.data() + tdOff, sizeof(td));
    const std::string ns = read_meta_string(v, td.namespaceIndex);
    const std::string nm = read_meta_string(v, td.nameIndex);
    if (nm.empty()) return "object";
    return ns.empty() ? nm : ns + "." + nm;
}

static bool read_remote_type(const MetaView &v, int32_t typeIndex, Il2CppTypeRemote &t) {
    if (typeIndex < 0 || v.hdr.typesOffset <= 0 || v.hdr.typesCount <= 0) return false;
    if (typeIndex >= v.hdr.typesCount) return false;
    const size_t off = (size_t)v.hdr.typesOffset + (size_t)typeIndex * sizeof(Il2CppTypeRemote);
    if (off + sizeof(Il2CppTypeRemote) > v.blob.size()) return false;
    std::memcpy(&t, v.blob.data() + off, sizeof(t));
    return true;
}

static std::string type_name_from_type(const MetaView &v, int32_t typeIndex) {
    if (typeIndex < 0) return "void";
    Il2CppTypeRemote t{};
    if (!read_remote_type(v, typeIndex, t)) return "object";
    switch (t.type) {
    case 0x01: return "void";
    case 0x02: return "bool";
    case 0x03: return "char";
    case 0x04: return "sbyte";
    case 0x05: return "byte";
    case 0x06: return "short";
    case 0x07: return "ushort";
    case 0x08: return "int";
    case 0x09: return "uint";
    case 0x0a: return "long";
    case 0x0b: return "ulong";
    case 0x0c: return "float";
    case 0x0d: return "double";
    case 0x0e: return "string";
    case 0x11: return "IntPtr";
    case 0x12: return "UIntPtr";
    case 0x1c: return "object";
    case 0x14:
    case 0x1d: return type_def_name(v, t.dataIndex) + "[]";
    default: return type_def_name(v, t.dataIndex);
    }
}

static bool load_meta_view(pid_t pid, uintptr_t remote, MetaView &out) {
    MetaHeader hdr{};
    if (!mem_read(pid, remote, &hdr, sizeof(hdr))) return false;
    if (hdr.sanity != (int32_t)kMetaSanity) return false;
    size_t need = 0;
    auto bump = [&](int32_t off, int32_t cnt, size_t elem) {
        if (off > 0 && cnt > 0) {
            const size_t end = (size_t)off + (size_t)cnt * elem;
            need = std::max(need, end);
        }
    };
    bump(hdr.stringOffset, hdr.stringCount, 64);
    bump(hdr.typeDefinitionsOffset, hdr.typeDefinitionsCount, sizeof(TypeDef));
    bump(hdr.methodsOffset, hdr.methodsCount, sizeof(MethodDef));
    bump(hdr.fieldsOffset, hdr.fieldsCount, sizeof(FieldDef));
    bump(hdr.parametersOffset, hdr.parametersCount, sizeof(ParamDef));
    bump(hdr.imagesOffset, hdr.imagesCount, sizeof(ImageDef));
    bump(hdr.typesOffset, hdr.typesCount, sizeof(Il2CppTypeRemote));
    need = std::max(need, (size_t)hdr.stringOffset + (size_t)hdr.stringCount);
    need = std::min(need, size_t(64 * 1024 * 1024));
    if (need < sizeof(MetaHeader)) return false;
    out.pid = pid;
    out.base = remote;
    out.hdr = hdr;
    out.blob.resize(need);
    if (!mem_read(pid, remote, out.blob.data(), need)) return false;
    return true;
}

static std::string visibility(uint32_t flags) {
    switch (flags & 0x7) {
    case 0x1: return "public ";
    case 0x2: return "internal ";
    case 0x3: return "private ";
    case 0x4: return "protected ";
    default: return "internal ";
    }
}

static std::string dump_type_block(const MetaView &v, int typeIdx) {
    const size_t tdOff = (size_t)v.hdr.typeDefinitionsOffset + (size_t)typeIdx * sizeof(TypeDef);
    if (tdOff + sizeof(TypeDef) > v.blob.size()) return {};
    TypeDef td{};
    std::memcpy(&td, v.blob.data() + tdOff, sizeof(td));
    const std::string ns = read_meta_string(v, td.namespaceIndex);
    const std::string nm = read_meta_string(v, td.nameIndex);
    if (nm.empty()) return {};

    std::ostringstream o;
    o << "\n// Namespace: " << ns << "\n";
    o << visibility(td.flags);
    if ((td.flags & 0x80) && (td.flags & 0x100)) o << "static ";
    if (td.flags & 0x80) o << "abstract ";
    if (td.flags & 0x100) o << "sealed ";
    o << "class " << nm << "\n// Metadata token: 0x" << std::hex << td.token << std::dec << "\n{";

    for (uint16_t fi = 0; fi < td.field_count; ++fi) {
        const int32_t fidx = td.fieldStart + fi;
        const size_t fOff = (size_t)v.hdr.fieldsOffset + (size_t)fidx * sizeof(FieldDef);
        if (fOff + sizeof(FieldDef) > v.blob.size()) continue;
        FieldDef fd{};
        std::memcpy(&fd, v.blob.data() + fOff, sizeof(fd));
        o << "\n\t" << type_name_from_type(v, fd.typeIndex) << " "
          << read_meta_string(v, fd.nameIndex) << "; // 0x0";
    }

    for (uint16_t mi = 0; mi < td.method_count; ++mi) {
        const int32_t midx = td.methodStart + mi;
        const size_t mOff = (size_t)v.hdr.methodsOffset + (size_t)midx * sizeof(MethodDef);
        if (mOff + sizeof(MethodDef) > v.blob.size()) continue;
        MethodDef md{};
        std::memcpy(&md, v.blob.data() + mOff, sizeof(md));
        o << "\n\n\t// RVA: 0x0";
        if (md.flags & 0x0010) o << " | static";
        o << "\n\t" << type_name_from_type(v, md.returnType) << " "
          << read_meta_string(v, md.nameIndex) << "(";
        for (uint16_t pi = 0; pi < md.parameterCount; ++pi) {
            const int32_t pidx = md.parameterStart + pi;
            const size_t pOff = (size_t)v.hdr.parametersOffset + (size_t)pidx * sizeof(ParamDef);
            if (pOff + sizeof(ParamDef) > v.blob.size()) break;
            ParamDef pd{};
            std::memcpy(&pd, v.blob.data() + pOff, sizeof(pd));
            if (pi) o << ", ";
            o << type_name_from_type(v, pd.typeIndex) << " " << read_meta_string(v, pd.nameIndex);
        }
        o << ");";
    }
    o << "\n}\n";
    return o.str();
}

} // namespace

static int map_scan_priority(const MapsReg &m, uintptr_t il2cppBase) {
    if (m.perms[0] != 'r') return 0;
    const size_t len = (size_t)(m.end - m.start);
    if (len < 32768) return 0;
    if (m.path.find("global-metadata") != std::string::npos) return 100;
    if (m.path.find("libil2cpp.so") != std::string::npos) return 95;
    if (il2cppBase && m.start <= il2cppBase && m.end > il2cppBase) return 90;
    if (m.path.empty() && len >= 512 * 1024 && len <= 32 * 1024 * 1024) return 70;
    if (m.path.find(".apk") != std::string::npos && len <= 24 * 1024 * 1024) return 50;
    return 0;
}

bool metadata_find(pid_t pid, uintptr_t il2cppBase, const char *libPathHint, uintptr_t &metaRemote,
                   size_t &metaSize) {
    metaRemote = 0;
    metaSize = 0;
    g_meta_file_cache.clear();
    g_meta_file_header_off = 0;

    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return false;

    for (const auto &m : maps) {
        if (m.path.find("global-metadata") == std::string::npos) continue;
        ui_log("[metadata] GSpace/conRent cache: %s", m.path.c_str());
        uintptr_t found = 0;
        if (load_metadata_from_map(pid, m, found)) {
            metaRemote = found;
            metaSize = g_meta_file_cache.size() - g_meta_file_header_off;
            ui_log("[metadata] FAB11BAF @ 0x%llx (global-metadata.dat)", (unsigned long long)found);
            return true;
        }
        uintptr_t fileOff = 0;
        if (scan_file_path(m.path.c_str(), fileOff, g_meta_file_cache)) {
            g_meta_file_header_off = fileOff;
            metaRemote = fileOff;
            metaSize = g_meta_file_cache.size() - fileOff;
            ui_log("[metadata] FAB11BAF from path file");
            return true;
        }
    }

    std::vector<std::pair<int, const MapsReg *>> ranked;
    for (const auto &m : maps) {
        const int p = map_scan_priority(m, il2cppBase);
        if (p > 0) ranked.push_back({p, &m});
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const auto &a, const auto &b) { return a.first > b.first; });

    ui_log("[metadata] scanning %zu candidate maps…", ranked.size());
    const int64_t deadline = meta_now_ms() + 10000;
    int scanned = 0;
    for (const auto &entry : ranked) {
        if (meta_now_ms() > deadline) {
            ui_log("[metadata] scan time limit (10s)");
            break;
        }
        const MapsReg &m = *entry.second;
        ++scanned;
        if (scanned <= 5 || scanned % 4 == 0)
            ui_log("[metadata] map #%d pri=%d %s", scanned, entry.first,
                   m.path.empty() ? "[anon]" : m.path.c_str());
        const size_t len = (size_t)(m.end - m.start);
        uintptr_t found = 0;
        if (!scan_region(pid, m.start, len, found)) continue;
        metaRemote = found;
        metaSize = len - (found - m.start);
        ui_log("[metadata] FAB11BAF @ 0x%llx map=%s", (unsigned long long)found,
               m.path.empty() ? "[anon]" : m.path.c_str());
        return true;
    }

    if (libPathHint && libPathHint[0]) {
        char procRoot[640];
        std::snprintf(procRoot, sizeof(procRoot), "/proc/%d/root%s", (int)pid, libPathHint);
        ui_log("[metadata] try file %s", procRoot);
        uintptr_t off = 0;
        if (scan_file_path(procRoot, off, g_meta_file_cache)) {
            g_meta_file_header_off = off;
            metaRemote = off;
            metaSize = g_meta_file_cache.size() - off;
            ui_log("[metadata] FAB11BAF in lib file offset 0x%llx", (unsigned long long)off);
            return true;
        }
        if (scan_file_path(libPathHint, off, g_meta_file_cache)) {
            g_meta_file_header_off = off;
            metaRemote = off;
            metaSize = g_meta_file_cache.size() - off;
            ui_log("[metadata] FAB11BAF in lib path offset 0x%llx", (unsigned long long)off);
            return true;
        }
    }

    ui_log("[metadata] not found (%d maps scanned)", scanned);
    return false;
}

bool metadata_dump_run(pid_t pid, uintptr_t il2cppBase, uintptr_t metaRemote, size_t,
                       const std::string &outPath, const std::string &targetLabel, DumpLogFn log,
                       DumpProgressFn progress) {
    MetaView v{};
    if (!load_meta_view_cached(v, pid, metaRemote)) {
        if (log) log("ERROR: metadata load failed");
        return false;
    }

    auto logf = [&](const char *fmt, ...) {
        char buf[512];
        va_list ap;
        va_start(ap, fmt);
        std::vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (log) log(buf);
    };

    logf("metadata v%d types=%d images=%d (external / conRent-style)",
         v.hdr.version, v.hdr.typeDefinitionsCount, v.hdr.imagesCount);

    std::ofstream out(outPath, std::ios::trunc);
    if (!out.is_open()) {
        logf("ERROR: cannot open %s", outPath.c_str());
        return false;
    }

    out << "// IL2CPP Dumped (global-metadata / conRent-style)\n";
    out << "// Target: " << targetLabel << "\n";
    out << "// Base: 0x" << std::hex << il2cppBase << std::dec << "\n";
    out << "// NOTE: RVAs/field offsets need in-process il2cpp (conRent inject) for runtime values\n\n";

    int processed = 0;
    const int total = v.hdr.typeDefinitionsCount;
    const auto dump_all_types = [&]() {
        for (int ti = 0; ti < v.hdr.typeDefinitionsCount; ++ti) {
            out << dump_type_block(v, ti);
            ++processed;
        }
    };
    for (int img = 0; img < v.hdr.imagesCount; ++img) {
        const size_t iOff = (size_t)v.hdr.imagesOffset + (size_t)img * sizeof(ImageDef);
        if (iOff + sizeof(ImageDef) > v.blob.size()) continue;
        ImageDef id{};
        std::memcpy(&id, v.blob.data() + iOff, sizeof(id));
        out << "// Image " << img << ": " << read_meta_string(v, id.nameIndex) << "\n";
        for (uint32_t t = 0; t < id.typeCount; ++t) {
            const int typeIdx = id.typeStart + (int32_t)t;
            if (typeIdx < 0 || typeIdx >= v.hdr.typeDefinitionsCount) continue;
            out << dump_type_block(v, typeIdx);
            ++processed;
            if (progress && (processed % 50 == 0)) {
                DumpProgress pr{};
                pr.progress = total > 0 ? (float)processed / (float)total : 0.f;
                pr.totalClasses = total;
                pr.currentClass = processed;
                progress(pr);
            }
        }
    }
    if (processed == 0 && v.hdr.typeDefinitionsCount > 0) {
        logf("image walk empty — dumping %d type defs directly", v.hdr.typeDefinitionsCount);
        dump_all_types();
    }
    out.close();

    if (processed == 0) {
        logf("ERROR: metadata dump wrote 0 types (v%d)", v.hdr.version);
        return false;
    }
    logf("SUCCESS metadata dump.cs classes=%d path=%s", processed, outPath.c_str());
    if (progress) {
        DumpProgress done{};
        done.progress = 1.f;
        done.totalClasses = processed;
        done.currentClass = processed;
        progress(done);
    }
    return true;
}
