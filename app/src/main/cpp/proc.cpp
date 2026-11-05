#include "proc.hpp"
#include "mem.hpp"
#include <dirent.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

static std::string read_cmdline(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!f) return {};
    std::string all((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (char &c : all)
        if (c == '\0') c = ' ';
    while (!all.empty() && all.back() == ' ') all.pop_back();
    return all;
}

void proc_format_cmdline(pid_t pid, char *out, size_t outCap) {
    if (!out || !outCap) return;
    const std::string s = read_cmdline(pid);
    std::snprintf(out, outCap, "%s", s.c_str());
}

bool proc_maps_has_il2cpp(pid_t pid) {
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return false;
    for (const auto &m : maps) {
        if (m.path.find("il2cpp") != std::string::npos) return true;
        if (m.path.find("liblogic") != std::string::npos) return true;
        if (m.path.find("GameAssembly") != std::string::npos) return true;
        if (m.path.find("libcsharp") != std::string::npos) return true;
    }
    return false;
}

size_t proc_list_all(ProcCandidate *out, size_t maxOut) {
    if (!out || !maxOut) return 0;
    DIR *d = opendir("/proc");
    if (!d) return 0;
    size_t n = 0;
    struct dirent *e;
    while ((e = readdir(d)) != nullptr) {
        if (e->d_name[0] < '1' || e->d_name[0] > '9') continue;
        const pid_t pid = (pid_t)std::atoi(e->d_name);
        if (pid <= 0) continue;
        if (kill(pid, 0) != 0) continue;
        out[n].pid = pid;
        proc_format_cmdline(pid, out[n].cmdline, sizeof(out[n].cmdline));
        if (!out[n].cmdline[0]) continue;
        out[n].hasIl2Cpp = proc_maps_has_il2cpp(pid);
        if (++n >= maxOut) break;
    }
    closedir(d);
    return n;
}

bool proc_alive(pid_t pid) { return pid > 0 && kill(pid, 0) == 0; }

bool proc_probe_read(pid_t pid) {
    std::vector<MapsReg> maps;
    if (!mem_maps(pid, maps)) return false;
    int tried = 0;
    for (const auto &r : maps) {
        if (r.perms[0] != 'r' || r.end <= r.start) continue;
        uint8_t scratch[8] = {};
        if (mem_read(pid, r.start, scratch, sizeof(scratch))) return true;
        if (++tried >= 64) break;
    }
    return false;
}
