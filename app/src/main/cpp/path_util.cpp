#include "path_util.hpp"
#include <sys/stat.h>
#include <cctype>
#include <cstring>

static std::string g_filesDir = "/sdcard/Download";
static std::string g_sdcardDir = "/storage/emulated/0/Download";
static std::string g_ownPackage = "com.il2cpp.externaldump";

void ui_set_own_package(const char *packageId) {
    if (packageId && packageId[0]) g_ownPackage = packageId;
}

bool ui_is_own_process(pid_t pid, const std::string &cmdline) {
    const std::string pkg = package_from_cmdline(cmdline, pid);
    if (!g_ownPackage.empty() && pkg == g_ownPackage) return true;
    if (cmdline.find("com.il2cpp.externaldump") != std::string::npos) return true;
    return false;
}

void ui_set_files_dir(const char *path) {
    if (path && path[0]) g_filesDir = path;
}

void ui_set_sdcard_dir(const char *path) {
    if (path && path[0]) g_sdcardDir = path;
}

std::string ui_sdcard_dir() { return g_sdcardDir; }

bool ensure_directory(const std::string &dir) {
    if (dir.empty()) return false;
    struct stat st{};
    if (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) return true;
    return mkdir(dir.c_str(), 0777) == 0 || (stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode));
}

std::string package_from_cmdline(const std::string &cmdline, pid_t pidFallback) {
    std::string pkg;
    if (!cmdline.empty()) {
        const size_t cut = cmdline.find_first_of(" \t");
        pkg = cut == std::string::npos ? cmdline : cmdline.substr(0, cut);
    }
    if (pkg.empty() || pkg.rfind("manual", 0) == 0)
        pkg = "pid_" + std::to_string(pidFallback);
    for (char &c : pkg) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_')) c = '_';
    }
    if (pkg.empty()) pkg = "unknown";
    return pkg;
}

std::string dump_output_path(const std::string &cmdline, pid_t pid) {
    const std::string pkg = package_from_cmdline(cmdline, pid);
    ensure_directory(g_sdcardDir);
    return g_sdcardDir + "/" + pkg + "_dump.cs";
}
