#pragma once
#include <string>
#include <sys/types.h>

void ui_set_files_dir(const char *path);
void ui_set_sdcard_dir(const char *path);

std::string ui_sdcard_dir();
std::string package_from_cmdline(const std::string &cmdline, pid_t pidFallback);
std::string dump_output_path(const std::string &cmdline, pid_t pid);
bool ensure_directory(const std::string &dir);
