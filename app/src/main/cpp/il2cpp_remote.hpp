#pragma once
#include "dump_cs_engine.hpp"
#include "remote_call.hpp"
#include "remote_il2cpp.hpp"
#include <sys/types.h>
#include <string>
#include <unordered_map>

class RemoteIl2CppExecutor {
  public:
    pid_t pid = 0;
    RemoteIl2CppInfo info{};

    bool open(pid_t target, char *err, size_t errCap);
    void close();
    bool run_dump(const std::string &outPath, const std::string &targetCmdline, DumpLogFn log,
                  DumpProgressFn progress);

  private:
    RemoteSession session_{};
    bool sessionOpen_ = false;
    int scratchSlot_ = 0;
    std::unordered_map<std::string, uintptr_t> sym_;

    uintptr_t scratch(size_t bytes);
    bool resolve_syms(char *err, size_t errCap);
    bool call0(const char *name, uintptr_t &ret);
    bool call1(const char *name, uintptr_t a0, uintptr_t &ret);
    bool call2(const char *name, uintptr_t a0, uintptr_t a1, uintptr_t &ret);
    bool call2_out(const char *name, uintptr_t a0, uintptr_t outRemote, uintptr_t &ret);
    bool read_cstr(uintptr_t remote, std::string &out);
    uintptr_t sym(const char *name) const;
};
