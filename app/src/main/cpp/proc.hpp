#pragma once
#include <cstddef>
#include <sys/types.h>

struct ProcCandidate {
    pid_t pid = 0;
    char cmdline[256] = {};
    bool hasIl2Cpp = false;
};

void proc_format_cmdline(pid_t pid, char *out, size_t outCap);
size_t proc_list_all(ProcCandidate *out, size_t maxOut);
/** Count of numeric entries under /proc (approx live PIDs). */
size_t proc_list_scan_total();
bool proc_alive(pid_t pid);
bool proc_probe_read(pid_t pid);
bool proc_maps_has_il2cpp(pid_t pid);
