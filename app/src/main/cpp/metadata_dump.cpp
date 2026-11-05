#include "metadata_dump.hpp"
#include "mem.hpp"
#include "remote_elf.hpp"
#include "ui_log.hpp"

#include <algorithm>
#include <cstddef>
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
constexpr size_t kTypeDefStrideV29 = 0x58;
constexpr size_t kMethodDefStrideV31 = 0x24;
constexpr size_t kMethodDefStrideV29 = 0x20;
constexpr size_t kImageDefStrideV24 = 0x28;
constexpr size_t kFieldDefStrideV19 = 12;
constexpr size_t kParamDefStrideV25 = 12;
constexpr size_t kMetaHeaderV29Size = 256;

#pragma pack(push, 1)
struct MetaHeaderV29 {
    uint32_t sanity;
    int32_t version;
    uint32_t stringLiteralOffset;
    int32_t stringLiteralSize;
    uint32_t stringLiteralDataOffset;
    int32_t stringLiteralDataSize;
    uint32_t stringOffset;
    int32_t stringSize;
    uint32_t eventsOffset;
    int32_t eventsSize;
    uint32_t propertiesOffset;
    int32_t propertiesSize;
    uint32_t methodsOffset;
    int32_t methodsSize;
    uint32_t parameterDefaultValuesOffset;
    int32_t parameterDefaultValuesSize;
    uint32_t fieldDefaultValuesOffset;
    int32_t fieldDefaultValuesSize;
    uint32_t fieldAndParameterDefaultValueDataOffset;
    int32_t fieldAndParameterDefaultValueDataSize;
    int32_t fieldMarshaledSizesOffset;
    int32_t fieldMarshaledSizesSize;
    uint32_t parametersOffset;
    int32_t parametersSize;
    uint32_t fieldsOffset;
    int32_t fieldsSize;
    uint32_t genericParametersOffset;
    int32_t genericParametersSize;
    uint32_t genericParameterConstraintsOffset;
    int32_t genericParameterConstraintsSize;
    uint32_t genericContainersOffset;
    int32_t genericContainersSize;
    uint32_t nestedTypesOffset;
    int32_t nestedTypesSize;
    uint32_t interfacesOffset;
    int32_t interfacesSize;
    uint32_t vtableMethodsOffset;
    int32_t vtableMethodsSize;
    int32_t interfaceOffsetsOffset;
    int32_t interfaceOffsetsSize;
    uint32_t typeDefinitionsOffset;
    int32_t typeDefinitionsSize;
    uint32_t imagesOffset;
    int32_t imagesSize;
    uint32_t assembliesOffset;
    int32_t assembliesSize;
    uint32_t fieldRefsOffset;
    int32_t fieldRefsSize;
    int32_t referencedAssembliesOffset;
    int32_t referencedAssembliesSize;
    uint32_t attributeDataOffset;
    int32_t attributeDataSize;
    uint32_t attributeDataRangeOffset;
    int32_t attributeDataRangeSize;
    int32_t unresolvedVirtualCallParameterTypesOffset;
    int32_t unresolvedVirtualCallParameterTypesSize;
    int32_t unresolvedVirtualCallParameterRangesOffset;
    int32_t unresolvedVirtualCallParameterRangesSize;
    int32_t windowsRuntimeTypeNamesOffset;
    int32_t windowsRuntimeTypeNamesSize;
    int32_t windowsRuntimeStringsOffset;
    int32_t windowsRuntimeStringsSize;
    int32_t exportedTypeDefinitionsOffset;
    int32_t exportedTypeDefinitionsSize;
};

struct MetaHeaderLegacy {
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
};

struct TypeDefV29 {
    uint32_t nameIndex;
    uint32_t namespaceIndex;
    int32_t byvalTypeIndex;
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

struct MethodDefV31 {
    uint32_t nameIndex;
    int32_t declaringType;
    int32_t returnType;
    int32_t returnParameterToken;
    int32_t parameterStart;
    int32_t genericContainerIndex;
    uint32_t token;
    uint16_t flags;
    uint16_t iflags;
    uint16_t slot;
    uint16_t parameterCount;
};

struct FieldDefV19 {
    uint32_t nameIndex;
    int32_t typeIndex;
    uint32_t token;
};

struct ParamDefV25 {
    uint32_t nameIndex;
    uint32_t token;
    int32_t typeIndex;
};

struct ImageDefV24 {
    uint32_t nameIndex;
    int32_t assemblyIndex;
    int32_t typeStart;
    uint32_t typeCount;
    int32_t exportedTypeStart;
    uint32_t exportedTypeCount;
    int32_t entryPointIndex;
    uint32_t token;
    int32_t customAttributeStart;
    uint32_t customAttributeCount;
};
#pragma pack(pop)

struct MetaView {
    pid_t pid = 0;
    uintptr_t base = 0;
    int32_t version = 0;
    bool headerV29 = false;
    uint32_t stringOffset = 0;
    int32_t stringSize = 0;
    uint32_t typeDefinitionsOffset = 0;
    int32_t typeDefinitionsSize = 0;
    int32_t typeDefinitionsCount = 0;
    size_t typeDefStride = kTypeDefStrideV29;
    uint32_t methodsOffset = 0;
    int32_t methodsSize = 0;
    size_t methodStride = kMethodDefStrideV31;
    uint32_t fieldsOffset = 0;
    int32_t fieldsSize = 0;
    uint32_t parametersOffset = 0;
    int32_t parametersSize = 0;
    uint32_t imagesOffset = 0;
    int32_t imagesSize = 0;
    int32_t imageCount = 0;
    size_t imageStride = kImageDefStrideV24;
    std::vector<uint8_t> blob;
};

static int64_t meta_now_ms() {
    struct timespec ts {};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static std::vector<uint8_t> g_meta_file_cache;
static size_t g_meta_file_header_off = 0;

static bool scan_file_path(const char *path, uintptr_t &foundRemote, std::vector<uint8_t> &fileCopy);
static bool scan_bytes_for_header(const uint8_t *data, size_t len, size_t &offOut);
static bool scan_region(pid_t pid, uintptr_t start, size_t len, uintptr_t &found);
static bool load_metadata_from_map(pid_t pid, const MapsReg &m, uintptr_t &metaRemote);
static size_t blob_need_v29(const MetaHeaderV29 &h);

static void log_header_reject_v29(const MetaHeaderV29 &h, size_t blobLen, const char *why) {
    const int types = h.typeDefinitionsSize / (int)kTypeDefStrideV29;
    ui_log("[metadata] header reject (%s) v=%d typeSz=%d tdo=%u imgsSz=%d (~%d types) blob=%zu",
           why, h.version, h.typeDefinitionsSize, h.typeDefinitionsOffset, h.imagesSize, types,
           blobLen);
}

static bool section_in_blob(uint32_t off, int32_t sz, size_t blobLen) {
    if (off == 0 || sz <= 0) return true;
    if ((size_t)off >= blobLen) return false;
    return (size_t)off + (size_t)sz <= blobLen;
}

static bool validate_meta_header_v29(const MetaHeaderV29 &h, size_t blobLen) {
    if (h.sanity != kMetaSanity) return false;
    if (h.version < 29 || h.version > 31) return false;
    if (h.typeDefinitionsSize <= 0 || h.typeDefinitionsSize % (int32_t)kTypeDefStrideV29 != 0)
        return false;
    if (h.typeDefinitionsOffset == 0) return false;
    if (!section_in_blob(h.typeDefinitionsOffset, h.typeDefinitionsSize, blobLen)) return false;
    if (h.stringOffset == 0 || !section_in_blob(h.stringOffset, h.stringSize, blobLen)) return false;
    if (h.methodsSize > 0 && h.methodsSize % (int32_t)(h.version >= 31 ? kMethodDefStrideV31
                                                                               : kMethodDefStrideV29) != 0)
        return false;
    if (h.imagesSize > 0 && h.imagesSize % (int32_t)kImageDefStrideV24 != 0) return false;
    return true;
}

static bool validate_meta_header_legacy(const MetaHeaderLegacy &h, size_t blobLen) {
    if (h.sanity != (int32_t)kMetaSanity) return false;
    if (h.version < 16 || h.version >= 29) return false;
    if (h.typeDefinitionsCount <= 0 || h.typeDefinitionsCount > 500000) return false;
    if (h.typeDefinitionsOffset <= 0) return false;
    if (blobLen > 0 && (size_t)h.typeDefinitionsOffset >= blobLen) return false;
    if (h.imagesCount < 0 || h.imagesCount > 65535) return false;
    return true;
}

static bool meta_view_apply_v29(MetaView &v, const MetaHeaderV29 &h) {
    v.version = h.version;
    v.headerV29 = true;
    v.stringOffset = h.stringOffset;
    v.stringSize = h.stringSize;
    v.typeDefinitionsOffset = h.typeDefinitionsOffset;
    v.typeDefinitionsSize = h.typeDefinitionsSize;
    v.typeDefinitionsCount = h.typeDefinitionsSize / (int32_t)kTypeDefStrideV29;
    v.typeDefStride = kTypeDefStrideV29;
    v.methodsOffset = h.methodsOffset;
    v.methodsSize = h.methodsSize;
    v.methodStride = h.version >= 31 ? kMethodDefStrideV31 : kMethodDefStrideV29;
    v.fieldsOffset = h.fieldsOffset;
    v.fieldsSize = h.fieldsSize;
    v.parametersOffset = h.parametersOffset;
    v.parametersSize = h.parametersSize;
    v.imagesOffset = h.imagesOffset;
    v.imagesSize = h.imagesSize;
    v.imageCount = h.imagesSize > 0 ? h.imagesSize / (int32_t)kImageDefStrideV24 : 0;
    v.imageStride = kImageDefStrideV24;
    return v.typeDefinitionsCount > 0;
}

static bool meta_view_apply_legacy(MetaView &v, const MetaHeaderLegacy &h) {
    v.version = h.version;
    v.headerV29 = false;
    v.stringOffset = (uint32_t)h.stringOffset;
    v.stringSize = h.stringCount;
    v.typeDefinitionsOffset = (uint32_t)h.typeDefinitionsOffset;
    v.typeDefinitionsSize = h.typeDefinitionsCount * (int32_t)kTypeDefStrideV29;
    v.typeDefinitionsCount = h.typeDefinitionsCount;
    v.typeDefStride = kTypeDefStrideV29;
    v.methodsOffset = (uint32_t)h.methodsOffset;
    v.methodsSize = h.methodsCount * (int32_t)kMethodDefStrideV29;
    v.methodStride = kMethodDefStrideV29;
    v.fieldsOffset = (uint32_t)h.fieldsOffset;
    v.fieldsSize = h.fieldsCount * (int32_t)kFieldDefStrideV19;
    v.parametersOffset = (uint32_t)h.parametersOffset;
    v.parametersSize = h.parametersCount * (int32_t)kParamDefStrideV25;
    v.imagesOffset = (uint32_t)h.imagesOffset;
    v.imagesSize = h.imagesCount * (int32_t)kImageDefStrideV24;
    v.imageCount = h.imagesCount;
    v.imageStride = kImageDefStrideV24;
    return v.typeDefinitionsCount > 0;
}

static bool meta_view_init_from_blob(MetaView &v) {
    if (v.blob.size() < 8) return false;
    int32_t version = 0;
    std::memcpy(&version, v.blob.data() + 4, sizeof(version));
    if (version >= 29) {
        if (v.blob.size() < kMetaHeaderV29Size) return false;
        MetaHeaderV29 h{};
        std::memcpy(&h, v.blob.data(), sizeof(h));
        if (!validate_meta_header_v29(h, v.blob.size())) return false;
        return meta_view_apply_v29(v, h);
    }
    if (v.blob.size() < sizeof(MetaHeaderLegacy)) return false;
    MetaHeaderLegacy h{};
    std::memcpy(&h, v.blob.data(), sizeof(h));
    if (!validate_meta_header_legacy(h, v.blob.size())) return false;
    return meta_view_apply_legacy(v, h);
}

static bool try_metadata_blob_accept(std::vector<uint8_t> &buf, size_t header_off = 0) {
    if (header_off >= buf.size()) return false;
    MetaView probe{};
    probe.blob.assign(buf.begin() + (ptrdiff_t)header_off, buf.end());
    if (!meta_view_init_from_blob(probe)) return false;
    if (header_off > 0) {
        g_meta_file_header_off = header_off;
        g_meta_file_cache = std::move(buf);
        buf = g_meta_file_cache;
    }
    return true;
}

static bool try_decrypt_il2cpp_encrypt(std::vector<uint8_t> &buf) {
    if (buf.size() < 1028 + 64u * 4u) return false;
    uint32_t kl_field = 0;
    std::memcpy(&kl_field, buf.data() + 1024, sizeof(kl_field));
    const uint32_t kl = kl_field & 0xffffu;
    if (kl < 64 || kl > 256) {
        ui_log("[metadata] Il2CppEncrypt skip kl_field=0x%x kl=%u", kl_field, kl);
        return false;
    }
    const size_t key_off = 1028;
    const size_t payload_off = key_off + (size_t)kl * 4u;
    if (buf.size() <= payload_off + 64) return false;
    auto *keys = reinterpret_cast<uint32_t *>(buf.data() + key_off);
    auto *enc = reinterpret_cast<uint32_t *>(buf.data() + payload_off);
    const size_t nwords = (buf.size() - payload_off) / 4;
    if (nwords == 0) return false;
    for (size_t i = 0; i < nwords; ++i) {
        const size_t key_index = kl ? (i + (i / kl)) % kl : 0;
        enc[i] ^= keys[key_index];
    }
    std::vector<uint8_t> merged;
    merged.resize(1024 + (buf.size() - payload_off));
    std::memcpy(merged.data(), buf.data(), 1024);
    std::memcpy(merged.data() + 1024, buf.data() + payload_off, buf.size() - payload_off);
    buf.swap(merged);
    ui_log("[metadata] Il2CppEncrypt decrypt kl=%u out=%zu", kl, buf.size());
    return true;
}

static bool try_decrypt_mlbb_legacy(std::vector<uint8_t> &buf) {
    if (buf.size() < 512) return false;
    uint32_t magic = 0;
    std::memcpy(&magic, buf.data(), sizeof(magic));
    if (magic != 0xA28C4102u) return false;
    magic = kMetaSanity;
    std::memcpy(buf.data(), &magic, sizeof(magic));
    auto xor_range = [&](size_t off, size_t len) {
        for (size_t i = off; i < off + len && i < buf.size(); ++i) buf[i] ^= 0xC3;
    };
    xor_range(4, 268);
    for (int i = 0; i < 0x30; i += 8) {
        int32_t block_off = 0, block_len = 0;
        std::memcpy(&block_off, buf.data() + (size_t)i + 8, 4);
        std::memcpy(&block_len, buf.data() + (size_t)i + 12, 4);
        if (block_off <= 0 || block_len <= 0) continue;
        if ((size_t)block_off + (size_t)block_len > buf.size()) continue;
        xor_range((size_t)block_off, (size_t)block_len);
    }
    ui_log("[metadata] MLBB legacy decrypt (0xA28C4102 → FAB11BAF)");
    return true;
}

static bool try_decrypt_mlbb_full_xor(std::vector<uint8_t> &buf, uint8_t key, size_t start) {
    if (start >= buf.size()) return false;
    std::vector<uint8_t> c = buf;
    for (size_t i = start; i < c.size(); ++i) c[i] ^= key;
    if (try_metadata_blob_accept(c, 0)) {
        buf = std::move(c);
        ui_log("[metadata] MLBB xor 0x%02x from +%zu", key, start);
        return true;
    }
    if (start <= 1024 && c.size() > 1024 + kMetaHeaderV29Size &&
        try_metadata_blob_accept(c, 1024)) {
        buf = std::move(c);
        ui_log("[metadata] MLBB xor 0x%02x @+1024", key);
        return true;
    }
    return false;
}

static bool try_decrypt_mlbb_v1024_wrapper(std::vector<uint8_t> &buf) {
    if (buf.size() < kMetaHeaderV29Size + 1024) return false;
    int32_t version = 0;
    std::memcpy(&version, buf.data() + 4, sizeof(version));
    if (version != 1024) return false;

    if (try_metadata_blob_accept(buf, 1024)) {
        ui_log("[metadata] MLBB v1024 wrapper — header @ +1024");
        return true;
    }

    for (uint8_t key : {uint8_t(0xC3), uint8_t(0x96), uint8_t(0x5A), uint8_t(0xFF)}) {
        if (try_decrypt_mlbb_full_xor(buf, key, 4)) return true;
        if (try_decrypt_mlbb_full_xor(buf, key, 1024)) return true;
    }

    const uint8_t keys[] = {0xC3, 0x5A, 0xA5, 0x96, 0x69, 0xFF, 0x55, 0xAA};
    for (uint8_t key : keys) {
        std::vector<uint8_t> c = buf;
        for (size_t i = 1024; i < c.size(); ++i) c[i] ^= key;
        for (size_t i = 4; i < 1024; ++i) c[i] ^= key;
        if (try_metadata_blob_accept(c, 0)) {
            buf = std::move(c);
            ui_log("[metadata] MLBB v1024 xor key=0x%02x (full)", key);
            return true;
        }
        if (try_metadata_blob_accept(c, 1024)) {
            buf = std::move(c);
            ui_log("[metadata] MLBB v1024 xor key=0x%02x @+1024", key);
            return true;
        }
    }
    return false;
}

static bool metadata_try_decrypt_file(std::vector<uint8_t> &buf) {
    if (buf.size() < 8) return false;
    MetaView probe{};
    probe.blob = buf;
    if (meta_view_init_from_blob(probe)) return false;

    uint32_t sanity = 0;
    int32_t version = 0;
    std::memcpy(&sanity, buf.data(), sizeof(sanity));
    std::memcpy(&version, buf.data() + 4, sizeof(version));
    const bool encrypted_hint =
        sanity == kMetaSanity && (version == 1024 || version > 31 || (version > 0 && version < 16));

    if (encrypted_hint) {
        ui_log("[metadata] encrypted global-metadata (v=%d) — MLBB/liblogic decrypt", version);
        if (version == 1024 && try_decrypt_mlbb_v1024_wrapper(buf)) return true;
        if (version != 1024) {
            std::vector<uint8_t> copy = buf;
            if (try_decrypt_il2cpp_encrypt(copy)) {
                if (try_metadata_blob_accept(copy, 0)) {
                    buf.swap(copy);
                    return true;
                }
                size_t hdr_off = 0;
                if (scan_bytes_for_header(copy.data(), copy.size(), hdr_off) &&
                    try_metadata_blob_accept(copy, hdr_off)) {
                    buf.swap(copy);
                    return true;
                }
            }
        }
    }
    std::vector<uint8_t> copy = buf;
    if (try_decrypt_mlbb_legacy(copy)) {
        probe.blob = copy;
        if (meta_view_init_from_blob(probe)) {
            buf.swap(copy);
            return true;
        }
    }
    return false;
}

static bool metadata_load_from_remote(pid_t pid, uintptr_t remote, uintptr_t &metaRemote,
                                      size_t &metaSize) {
    uint32_t sanity = 0;
    int32_t version = 0;
    if (!mem_read(pid, remote, &sanity, sizeof(sanity)) ||
        !mem_read(pid, remote + 4, &version, sizeof(version)))
        return false;
    size_t headerOff = 0;
    if (sanity == kMetaSanity && version == 1024) {
        headerOff = 1024;
        if (!mem_read(pid, remote + headerOff, &sanity, sizeof(sanity)) ||
            !mem_read(pid, remote + headerOff + 4, &version, sizeof(version)))
            return false;
    }
    MetaHeaderV29 h{};
    if (!mem_read(pid, remote + headerOff, &h, sizeof(h))) return false;
    if (!validate_meta_header_v29(h, 64 * 1024 * 1024)) {
        if (headerOff == 0 && sanity == kMetaSanity && version == 1024) {
            constexpr size_t kProbe = 4755456;
            g_meta_file_cache.resize(kProbe);
            if (!mem_read(pid, remote, g_meta_file_cache.data(), kProbe)) {
                g_meta_file_cache.clear();
                return false;
            }
            MetaView probe{};
            probe.blob = g_meta_file_cache;
            if (metadata_try_decrypt_file(g_meta_file_cache) && meta_view_init_from_blob(probe)) {
                g_meta_file_header_off = 0;
                metaRemote = remote;
                metaSize = g_meta_file_cache.size();
                return true;
            }
            g_meta_file_cache.clear();
        }
        return false;
    }
    const size_t need = blob_need_v29(h);
    g_meta_file_cache.resize(need + headerOff);
    if (!mem_read(pid, remote, g_meta_file_cache.data(), need + headerOff)) {
        g_meta_file_cache.clear();
        return false;
    }
    g_meta_file_header_off = headerOff;
    metaRemote = remote + headerOff;
    metaSize = need;
    return true;
}

static bool metadata_scan_il2cpp_data_pointers(pid_t pid, const char *libPathHint,
                                             uintptr_t il2cppBase, uintptr_t &metaRemote,
                                             size_t &metaSize) {
    if (!libPathHint || !libPathHint[0]) return false;
    std::string libName = libPathHint;
    const size_t slash = libName.find_last_of('/');
    if (slash != std::string::npos) libName = libName.substr(slash + 1);

    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return false;
    ui_log("[metadata] scan %s .data for metadata ptr (mlbb-pure / conRent runtime)", libName.c_str());

    for (const auto &m : maps) {
        if (m.path.find(libName) == std::string::npos) continue;
        if (m.perms[0] != 'r' || m.perms[1] != 'w') continue;
        if (m.perms[2] == 'x') continue;
        const size_t len = (size_t)(m.end - m.start);
        if (len < 4096 || len > 32 * 1024 * 1024) continue;
        for (size_t off = 0; off + sizeof(uintptr_t) <= len; off += 0x40) {
            uintptr_t ptr = 0;
            if (!mem_read(pid, m.start + off, &ptr, sizeof(ptr))) continue;
            if (!mem_ptr_ok(ptr)) continue;
            if (il2cppBase && ptr >= il2cppBase && ptr < il2cppBase + 0x20000000ULL) continue;
            if (metadata_load_from_remote(pid, ptr, metaRemote, metaSize)) {
                ui_log("[metadata] metadata* from %s @ 0x%llx (ptr in .data+0x%zx)",
                       libName.c_str(), (unsigned long long)ptr, off);
                return true;
            }
        }
    }
    ui_log("[metadata] %s .data pointer scan — no metadata ptr", libName.c_str());
    return false;
}

static bool metadata_find_elf_global(pid_t pid, uintptr_t il2cppBase, uintptr_t &metaRemote,
                                     size_t &metaSize) {
    if (!il2cppBase) return false;
    static const char *kSyms[] = {"s_GlobalMetadata",
                                  "_ZN6il2cpp2vm13MetadataCache15s_GlobalMetadataE",
                                  "g_Metadata"};
    for (const char *sym : kSyms) {
        uintptr_t symAddr = 0;
        if (!elf_remote_sym(pid, il2cppBase, sym, symAddr) || !symAddr) continue;
        uintptr_t ptr = 0;
        if (mem_read(pid, symAddr, &ptr, sizeof(ptr)) && mem_ptr_ok(ptr) &&
            metadata_load_from_remote(pid, ptr, metaRemote, metaSize)) {
            ui_log("[metadata] %s -> metadata @ 0x%llx", sym, (unsigned long long)ptr);
            return true;
        }
        if (metadata_load_from_remote(pid, symAddr, metaRemote, metaSize)) {
            ui_log("[metadata] %s direct @ 0x%llx", sym, (unsigned long long)symAddr);
            return true;
        }
    }
    return false;
}

static bool metadata_scan_runtime_decrypted(pid_t pid, uintptr_t il2cppBase, uintptr_t &metaRemote,
                                            size_t &metaSize) {
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return false;
    struct Ranked {
        int pri;
        const MapsReg *m;
    };
    std::vector<Ranked> ranked;
    constexpr size_t kMlbbMetaSizeHint = 4755456;
    for (const auto &m : maps) {
        if (m.perms[0] != 'r') continue;
        const size_t len = (size_t)(m.end - m.start);
        if (len < 768 * 1024 || len > 48 * 1024 * 1024) continue;
        if (m.path.find("global-metadata") != std::string::npos) continue;
        if (m.path.find(".so") != std::string::npos) continue;
        const std::string &p = m.path;
        if (p.find("stack") != std::string::npos || p.find("tls") != std::string::npos) continue;
        if (p.find(".bss") != std::string::npos && len < 3 * 1024 * 1024) continue;
        if (p.find("/dev/") == 0 || p.find("dalvik") != std::string::npos) continue;
        if (p.find("mali") != std::string::npos) continue;
        const bool anonHeap =
            p.empty() || p.find("[anon:") != std::string::npos || p.find("libc_malloc") != std::string::npos;
        if (!anonHeap) continue;
        if (m.perms[1] != 'w' && p.find("libc_malloc") == std::string::npos) continue;
        int pri = 50;
        if (p.find("libc_malloc") != std::string::npos) pri += 80;
        if (len >= 3 * 1024 * 1024 && len <= 8 * 1024 * 1024) pri += 90;
        const int64_t d = (int64_t)len - (int64_t)kMlbbMetaSizeHint;
        if (d >= -512 * 1024 && d <= 512 * 1024) pri += 120;
        ranked.push_back({pri, &m});
    }
    std::sort(ranked.begin(), ranked.end(),
              [](const Ranked &a, const Ranked &b) { return a.pri > b.pri; });
    ui_log("[metadata] runtime decrypted scan (%zu maps, conRent-style in-memory metadata)…",
           ranked.size());
    const int64_t deadline = meta_now_ms() + 20000;
    int n = 0;
    for (const auto &e : ranked) {
        if (meta_now_ms() > deadline) break;
        const MapsReg &m = *e.m;
        ++n;
        if (n <= 8) ui_log("[metadata] runtime #%d pri=%d %s", n, e.pri,
                            m.path.empty() ? "[anon]" : m.path.c_str());
        uintptr_t found = 0;
        const size_t len = (size_t)(m.end - m.start);
        if (!scan_region(pid, m.start, len, found)) continue;
        if (!metadata_load_from_remote(pid, found, metaRemote, metaSize)) continue;
        g_meta_file_header_off = 0;
        ui_log("[metadata] decrypted metadata @ 0x%llx (%s)", (unsigned long long)found,
               m.path.empty() ? "anon" : m.path.c_str());
        return true;
    }
    return false;
}

static bool try_accept_header_at(const uint8_t *data, size_t len, size_t off, size_t &offOut) {
    if (off + 8 > len) return false;
    uint32_t sanity = 0;
    int32_t version = 0;
    std::memcpy(&sanity, data + off, sizeof(sanity));
    std::memcpy(&version, data + off + 4, sizeof(version));
    if (sanity != kMetaSanity) return false;
    MetaView tmp{};
    tmp.blob.assign(data + off, data + len);
    if (!meta_view_init_from_blob(tmp)) {
        if (off == 0 && sanity == kMetaSanity && version != 1024 && version >= 29 &&
            len >= kMetaHeaderV29Size) {
            MetaHeaderV29 h{};
            std::memcpy(&h, data + off, sizeof(h));
            log_header_reject_v29(h, len, "v29");
        }
        return false;
    }
    offOut = off;
    return true;
}

static bool try_metadata_from_file_paths(pid_t pid, const std::string &mapPath, uintptr_t &metaRemote,
                                          size_t &metaSize, const char *tag) {
    std::vector<std::string> paths;
    if (!mapPath.empty()) paths.push_back(mapPath);
    if (!mapPath.empty() && mapPath[0] == '/') {
        char procRoot[768];
        std::snprintf(procRoot, sizeof(procRoot), "/proc/%d/root%s", (int)pid, mapPath.c_str());
        paths.push_back(procRoot);
    }
    for (const auto &p : paths) {
        uintptr_t fileOff = 0;
        g_meta_file_cache.clear();
        if (!scan_file_path(p.c_str(), fileOff, g_meta_file_cache)) continue;
        g_meta_file_header_off = fileOff;
        metaRemote = fileOff;
        metaSize = g_meta_file_cache.size() - fileOff;
        MetaView mv{};
        mv.blob = g_meta_file_cache;
        if (!meta_view_init_from_blob(mv)) continue;
        ui_log("[metadata] FAB11BAF from %s (%s v=%d types=%d)", tag, p.c_str(), mv.version,
               mv.typeDefinitionsCount);
        return true;
    }
    return false;
}

static bool scan_bytes_for_header(const uint8_t *data, size_t len, size_t &offOut) {
    offOut = 0;
    if (len < kMetaHeaderV29Size) return false;
    if (try_accept_header_at(data, len, 0, offOut)) return true;
    const size_t step = 4096;
    for (size_t off = step; off + kMetaHeaderV29Size <= len; off += step) {
        for (size_t i = off; i + kMetaHeaderV29Size <= len && i < off + step + 4096; i += 4) {
            if (try_accept_header_at(data, len, i, offOut)) return true;
        }
    }
    return false;
}

static bool scan_region(pid_t pid, uintptr_t start, size_t len, uintptr_t &found) {
    if (len < kMetaHeaderV29Size) return false;
    constexpr size_t kMaxScan = 32 * 1024 * 1024;
    len = std::min(len, kMaxScan);
    const size_t step = 65536;
    std::vector<uint8_t> chunk(step + kMetaHeaderV29Size);
    for (size_t off = 0; off + kMetaHeaderV29Size <= len; off += step) {
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
    if (sz <= (long)kMetaHeaderV29Size || sz > 128 * 1024 * 1024) {
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
        if (!metadata_try_decrypt_file(fileCopy) ||
            !scan_bytes_for_header(fileCopy.data(), fileCopy.size(), off)) {
            fileCopy.clear();
            return false;
        }
    }
    foundRemote = off;
    return true;
}

static bool load_metadata_from_map(pid_t pid, const MapsReg &m, uintptr_t &metaRemote) {
    const size_t len = std::min((size_t)(m.end - m.start), size_t(128 * 1024 * 1024));
    g_meta_file_cache.assign(len, 0);
    if (!mem_read(pid, m.start, g_meta_file_cache.data(), len)) {
        ui_log("[metadata] mem_read failed map=0x%llx len=%zu", (unsigned long long)m.start, len);
        return false;
    }
    size_t off = 0;
    if (!scan_bytes_for_header(g_meta_file_cache.data(), len, off)) {
        if (metadata_try_decrypt_file(g_meta_file_cache) &&
            scan_bytes_for_header(g_meta_file_cache.data(), g_meta_file_cache.size(), off)) {
            ui_log("[metadata] decrypted disk metadata in map buffer");
        } else {
            uint32_t sanity = 0;
            int32_t version = 0;
            if (len >= 8) {
                std::memcpy(&sanity, g_meta_file_cache.data(), 4);
                std::memcpy(&version, g_meta_file_cache.data() + 4, 4);
            }
            ui_log("[metadata] no header in map (magic=%08x v=%d len=%zu)", sanity, version, len);
            if (sanity == kMetaSanity && version != 1024 && len >= kMetaHeaderV29Size) {
                MetaHeaderV29 peek{};
                std::memcpy(&peek, g_meta_file_cache.data(), sizeof(peek));
                log_header_reject_v29(peek, len, "map");
            }
            g_meta_file_cache.clear();
            return false;
        }
    }
    g_meta_file_header_off = off;
    metaRemote = m.start + off;
    MetaView mv{};
    mv.blob.assign(g_meta_file_cache.begin() + off, g_meta_file_cache.end());
    if (!meta_view_init_from_blob(mv)) {
        g_meta_file_cache.clear();
        return false;
    }
    ui_log("[metadata] loaded from map +0x%zx v=%d types=%d (Il2Cpp v29+ size/count)", off,
           mv.version, mv.typeDefinitionsCount);
    return true;
}

static bool load_meta_view(pid_t pid, uintptr_t remote, MetaView &out);

static bool load_meta_view_cached(MetaView &v, pid_t pid, uintptr_t metaRemote) {
    if (!g_meta_file_cache.empty()) {
        v.pid = pid;
        v.base = metaRemote;
        v.blob.assign(g_meta_file_cache.begin() + g_meta_file_header_off, g_meta_file_cache.end());
        return meta_view_init_from_blob(v);
    }
    return load_meta_view(pid, metaRemote, v);
}

static std::string read_meta_string(const MetaView &v, int32_t index) {
    if (index < 0) return {};
    const int32_t off = (int32_t)v.stringOffset + index;
    if (off < 0 || (size_t)off >= v.blob.size()) return {};
    if (v.stringSize > 0 && (size_t)off >= (size_t)v.stringOffset + (size_t)v.stringSize) return {};
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
    if (typeDefIndex < 0 || typeDefIndex >= v.typeDefinitionsCount) return "object";
    const size_t tdOff =
        (size_t)v.typeDefinitionsOffset + (size_t)typeDefIndex * v.typeDefStride;
    if (tdOff + v.typeDefStride > v.blob.size()) return "object";
    TypeDefV29 td{};
    const size_t cp = std::min(v.typeDefStride, sizeof(td));
    std::memcpy(&td, v.blob.data() + tdOff, cp);
    const std::string ns = read_meta_string(v, (int32_t)td.namespaceIndex);
    const std::string nm = read_meta_string(v, (int32_t)td.nameIndex);
    if (nm.empty()) return "object";
    return ns.empty() ? nm : ns + "." + nm;
}

static bool read_remote_type(const MetaView &, int32_t, Il2CppTypeRemote &) {
    return false;
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

static size_t blob_need_v29(const MetaHeaderV29 &h) {
    size_t need = kMetaHeaderV29Size;
    auto bump = [&](uint32_t off, int32_t sz) {
        if (off && sz > 0) need = std::max(need, (size_t)off + (size_t)sz);
    };
    bump(h.stringLiteralOffset, h.stringLiteralSize);
    bump(h.stringLiteralDataOffset, h.stringLiteralDataSize);
    bump(h.stringOffset, h.stringSize);
    bump(h.eventsOffset, h.eventsSize);
    bump(h.propertiesOffset, h.propertiesSize);
    bump(h.methodsOffset, h.methodsSize);
    bump(h.parameterDefaultValuesOffset, h.parameterDefaultValuesSize);
    bump(h.fieldDefaultValuesOffset, h.fieldDefaultValuesSize);
    bump(h.fieldAndParameterDefaultValueDataOffset, h.fieldAndParameterDefaultValueDataSize);
    bump((uint32_t)h.fieldMarshaledSizesOffset, h.fieldMarshaledSizesSize);
    bump(h.parametersOffset, h.parametersSize);
    bump(h.fieldsOffset, h.fieldsSize);
    bump(h.genericParametersOffset, h.genericParametersSize);
    bump(h.genericParameterConstraintsOffset, h.genericParameterConstraintsSize);
    bump(h.genericContainersOffset, h.genericContainersSize);
    bump(h.nestedTypesOffset, h.nestedTypesSize);
    bump(h.interfacesOffset, h.interfacesSize);
    bump(h.vtableMethodsOffset, h.vtableMethodsSize);
    bump((uint32_t)h.interfaceOffsetsOffset, h.interfaceOffsetsSize);
    bump(h.typeDefinitionsOffset, h.typeDefinitionsSize);
    bump(h.imagesOffset, h.imagesSize);
    bump(h.assembliesOffset, h.assembliesSize);
    bump(h.fieldRefsOffset, h.fieldRefsSize);
    bump((uint32_t)h.referencedAssembliesOffset, h.referencedAssembliesSize);
    bump(h.attributeDataOffset, h.attributeDataSize);
    bump(h.attributeDataRangeOffset, h.attributeDataRangeSize);
    return std::min(need, size_t(128 * 1024 * 1024));
}

static bool load_meta_view(pid_t pid, uintptr_t remote, MetaView &out) {
    MetaHeaderV29 h{};
    if (!mem_read(pid, remote, &h, sizeof(h))) return false;
    if (h.sanity != kMetaSanity) return false;
    size_t need = kMetaHeaderV29Size;
    if (h.version >= 29) {
        if (!mem_read(pid, remote, &h, sizeof(h))) return false;
        need = blob_need_v29(h);
    } else {
        MetaHeaderLegacy leg{};
        if (!mem_read(pid, remote, &leg, sizeof(leg))) return false;
        need = std::min((size_t)leg.stringOffset + (size_t)leg.stringCount,
                        size_t(128 * 1024 * 1024));
        need = std::max(need, sizeof(MetaHeaderLegacy));
    }
    out.pid = pid;
    out.base = remote;
    out.blob.resize(need);
    if (!mem_read(pid, remote, out.blob.data(), need)) return false;
    return meta_view_init_from_blob(out);
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
    const size_t tdOff = (size_t)v.typeDefinitionsOffset + (size_t)typeIdx * v.typeDefStride;
    if (tdOff + v.typeDefStride > v.blob.size()) return {};
    TypeDefV29 td{};
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
        const size_t fOff = (size_t)v.fieldsOffset + (size_t)fidx * kFieldDefStrideV19;
        if (fOff + kFieldDefStrideV19 > v.blob.size()) continue;
        FieldDefV19 fd{};
        std::memcpy(&fd, v.blob.data() + fOff, sizeof(fd));
        o << "\n\t" << type_name_from_type(v, fd.typeIndex) << " "
          << read_meta_string(v, fd.nameIndex) << "; // 0x0";
    }

    for (uint16_t mi = 0; mi < td.method_count; ++mi) {
        const int32_t midx = td.methodStart + mi;
        const size_t mOff = (size_t)v.methodsOffset + (size_t)midx * v.methodStride;
        if (mOff + v.methodStride > v.blob.size()) continue;
        MethodDefV31 md{};
        std::memset(&md, 0, sizeof(md));
        std::memcpy(&md, v.blob.data() + mOff, v.methodStride);
        o << "\n\n\t// RVA: 0x0";
        if (md.flags & 0x0010) o << " | static";
        o << "\n\t" << type_name_from_type(v, md.returnType) << " "
          << read_meta_string(v, md.nameIndex) << "(";
        for (uint16_t pi = 0; pi < md.parameterCount; ++pi) {
            const int32_t pidx = md.parameterStart + pi;
            const size_t pOff = (size_t)v.parametersOffset + (size_t)pidx * kParamDefStrideV25;
            if (pOff + kParamDefStrideV25 > v.blob.size()) break;
            ParamDefV25 pd{};
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
        if (try_metadata_from_file_paths(pid, m.path, metaRemote, metaSize, "file")) return true;
        uintptr_t found = 0;
        if (load_metadata_from_map(pid, m, found)) {
            metaRemote = found;
            metaSize = g_meta_file_cache.size() - g_meta_file_header_off;
            ui_log("[metadata] FAB11BAF @ 0x%llx (global-metadata.dat map)", (unsigned long long)found);
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

    ui_log("[metadata] ELF s_GlobalMetadata on lib base 0x%llx…", (unsigned long long)il2cppBase);
    if (metadata_find_elf_global(pid, il2cppBase, metaRemote, metaSize)) return true;
    if (metadata_scan_il2cpp_data_pointers(pid, libPathHint, il2cppBase, metaRemote, metaSize))
        return true;
    if (metadata_scan_runtime_decrypted(pid, il2cppBase, metaRemote, metaSize)) return true;

    ui_log("[metadata] not found (%d maps scanned)", scanned);
    ui_log("[metadata] MLBB: keep game in match/menu so liblogic loads decrypted metadata");
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

    logf("metadata v%d types=%d images=%d (Il2CppDumper v29+ / conRent-style names)",
         v.version, v.typeDefinitionsCount, v.imageCount);

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
    const int total = v.typeDefinitionsCount;
    const auto dump_all_types = [&]() {
        for (int ti = 0; ti < v.typeDefinitionsCount; ++ti) {
            out << dump_type_block(v, ti);
            ++processed;
        }
    };
    for (int img = 0; img < v.imageCount; ++img) {
        const size_t iOff = (size_t)v.imagesOffset + (size_t)img * v.imageStride;
        if (iOff + v.imageStride > v.blob.size()) continue;
        ImageDefV24 id{};
        std::memcpy(&id, v.blob.data() + iOff, sizeof(id));
        out << "// Image " << img << ": " << read_meta_string(v, id.nameIndex) << "\n";
        for (uint32_t t = 0; t < id.typeCount; ++t) {
            const int typeIdx = id.typeStart + (int32_t)t;
            if (typeIdx < 0 || typeIdx >= v.typeDefinitionsCount) continue;
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
    if (processed == 0 && v.typeDefinitionsCount > 0) {
        logf("image walk empty — dumping %d type defs directly", v.typeDefinitionsCount);
        dump_all_types();
    }
    out.close();

    if (processed == 0) {
        logf("ERROR: metadata dump wrote 0 types (v%d)", v.version);
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
