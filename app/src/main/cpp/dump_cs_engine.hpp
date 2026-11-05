#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <sys/types.h>

struct DumpCtx {
    pid_t pid = 0;
    uintptr_t il2cppBase = 0;
    uintptr_t il2cppEnd = 0;
    std::string libName;

    std::function<uintptr_t(const char *sym)> sym;
    /** a1 may be in-out iter pointer or out-parameter buffer in target address space. */
    std::function<bool(const char *name, uintptr_t a0, uintptr_t a1, uintptr_t &ret)> call2;
    std::function<bool(const char *name, uintptr_t a0, uintptr_t &ret)> call1;
    std::function<bool(const char *name, uintptr_t &ret)> call0;
    std::function<uintptr_t(size_t bytes)> scratch;
    std::function<bool(uintptr_t remote, std::string &out)> readCstr;
    std::function<bool(uintptr_t remote, void *buf, size_t n)> readMem;
};

struct DumpProgress {
    float progress = 0.f;
    int totalClasses = 0;
    int currentClass = 0;
    char imageName[128] = {};
};

using DumpLogFn = std::function<void(const char *)>;
using DumpProgressFn = std::function<void(const DumpProgress &)>;

bool dump_cs_run(DumpCtx &ctx, const std::string &outPath, const std::string &targetLabel,
                 DumpLogFn log, DumpProgressFn progress);
