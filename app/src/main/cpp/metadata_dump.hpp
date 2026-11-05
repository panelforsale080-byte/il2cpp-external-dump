#pragma once
#include "dump_cs_engine.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <sys/types.h>

bool metadata_find(pid_t pid, uintptr_t il2cppBase, uintptr_t &metaRemote, size_t &metaSize);
bool metadata_dump_run(pid_t pid, uintptr_t il2cppBase, uintptr_t metaRemote, size_t metaSize,
                       const std::string &outPath, const std::string &targetLabel, DumpLogFn log,
                       DumpProgressFn progress);
