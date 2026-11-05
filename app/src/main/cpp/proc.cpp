#include "proc.hpp"
#include "mem.hpp"
#include <dirent.h>
#include <unistd.h>
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static bool is_pid_dir(const char *name) {
    if (!name || !*name) return false;
    for (const char *p = name; *p; ++p) {
        if (!std::isdigit(static_cast<unsigned char>(*p))) return false;
    }
    return true;
}

static std::string read_cmdline(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/cmdline", std::ios::binary);
    if (!f) return {};
    std::string all((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    for (char &c : all)
        if (c == '\0') c = ' ';
    while (!all.empty() && all.back() == ' ') all.pop_back();
    return all;
}

static std::string read_comm(pid_t pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    if (!f) return {};
    std::string s;
    std::getline(f, s);
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    return s;
}

static bool maps_line_il2cpp_hint(const std::string &line) {
    if (line.find("il2cpp") != std::string::npos) return true;
    if (line.find("liblogic") != std::string::npos) return true;
    if (line.find("GameAssembly") != std::string::npos) return true;
    if (line.find("libcsharp") != std::string::npos) return true;
    if (line.find("global-metadata.dat") != std::string::npos) return true;
    if (line.find("libunity") != std::string::npos && line.find(".so") != std::string::npos)
        return true;
    if (line.find("libmain.so") != std::string::npos && line.find("/data/app/") != std::string::npos)
        return true;
    return false;
}

bool proc_maps_has_il2cpp(pid_t pid) {
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    if (!maps) return false;
    std::string line;
    while (std::getline(maps, line)) {
        if (maps_line_il2cpp_hint(line)) return true;
    }
    return false;
}

static void sanitize_label(char *out, size_t outCap) {
    if (!out || !outCap) return;
    for (size_t i = 0; out[i] && i + 1 < outCap; ++i) {
        const unsigned char c = static_cast<unsigned char>(out[i]);
        if (c < 0x20 || c == 0x7f) out[i] = ' ';
    }
}

void proc_format_cmdline(pid_t pid, char *out, size_t outCap) {
    if (!out || !outCap) return;
    std::string label = read_cmdline(pid);
    if (label.empty()) label = read_comm(pid);
    if (label.empty()) label = "unknown";
    std::snprintf(out, outCap, "%s", label.c_str());
    sanitize_label(out, outCap);
}

size_t proc_list_all(ProcCandidate *out, size_t maxOut) {
    if (!out || !maxOut) return 0;
    DIR *d = opendir("/proc");
    if (!d) return 0;

    std::vector<ProcCandidate> all;
    all.reserve(512);
    struct dirent *e;
    while ((e = readdir(d)) != nullptr) {
        if (!is_pid_dir(e->d_name)) continue;
        const pid_t pid = (pid_t)std::atoi(e->d_name);
        if (pid <= 0) continue;
        if (kill(pid, 0) != 0) continue;

        ProcCandidate c{};
        c.pid = pid;
        proc_format_cmdline(pid, c.cmdline, sizeof(c.cmdline));
        c.hasIl2Cpp = proc_maps_has_il2cpp(pid);
        all.push_back(c);
    }
    closedir(d);

    std::sort(all.begin(), all.end(), [](const ProcCandidate &a, const ProcCandidate &b) {
        if (a.hasIl2Cpp != b.hasIl2Cpp) return a.hasIl2Cpp > b.hasIl2Cpp;
        return a.pid < b.pid;
    });

    const size_t n = std::min(all.size(), maxOut);
    for (size_t i = 0; i < n; ++i) out[i] = all[i];
    return n;
}

size_t proc_list_scan_total() {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    size_t n = 0;
    while (struct dirent *e = readdir(d)) {
        if (is_pid_dir(e->d_name)) ++n;
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
