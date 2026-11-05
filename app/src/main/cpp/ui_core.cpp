#include "ui_core.hpp"
#include "proc.hpp"
#include "ui_log.hpp"
#include "clip_android.hpp"
#include "il2cpp_remote.hpp"

#include <android/log.h>
#include <GLES2/gl2.h>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"

static int g_width = 0, g_height = 0;
static int g_displayW = 0, g_displayH = 0;
ImVec2 initialScreenSize;
ImVec2 &ui_initial_screen_size() { return initialScreenSize; }

static bool g_glReady = false;
static bool g_imguiBackend = false;
static std::mutex g_glMu;
static const char *g_glslVersion = "#version 100";

static bool g_showMenu = true;
static bool g_logScrollBottom = true;
static bool g_filterIl2CppOnly = true;
static char g_search[128] = {};

static ProcCandidate g_procs[256];
static size_t g_procCount = 0;
static int g_selected = -1;
static pid_t g_selectedPid = 0;

static std::atomic<bool> g_dumpRunning{false};
static std::atomic<float> g_dumpProgress{0.f};
static char g_dumpStatus[256] = "Ready";

static std::string g_filesDir = "/sdcard/Download";

static void apply_menu_style() {
    ImGuiStyle &s = ImGui::GetStyle();
    ImVec4 *c = s.Colors;
    s.WindowRounding = 12.f;
    s.FrameRounding = 8.f;
    s.GrabRounding = 6.f;
    s.ScrollbarRounding = 8.f;
    s.WindowPadding = ImVec2(14.f, 12.f);
    s.ItemSpacing = ImVec2(10.f, 8.f);
    s.WindowBorderSize = 0.f;
    c[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.07f, 0.11f, 0.94f);
    c[ImGuiCol_TitleBg] = ImVec4(0.04f, 0.05f, 0.09f, 1.f);
    c[ImGuiCol_TitleBgActive] = ImVec4(0.12f, 0.22f, 0.45f, 1.f);
    c[ImGuiCol_Button] = ImVec4(0.15f, 0.42f, 0.78f, 0.85f);
    c[ImGuiCol_ButtonHovered] = ImVec4(0.20f, 0.55f, 0.95f, 1.f);
    c[ImGuiCol_ButtonActive] = ImVec4(0.10f, 0.35f, 0.65f, 1.f);
    c[ImGuiCol_Header] = ImVec4(0.12f, 0.35f, 0.62f, 0.55f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.18f, 0.48f, 0.82f, 0.75f);
    c[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.11f, 0.16f, 0.9f);
    c[ImGuiCol_CheckMark] = ImVec4(0.35f, 0.85f, 1.f, 1.f);
    c[ImGuiCol_Separator] = ImVec4(0.25f, 0.35f, 0.55f, 0.5f);
}

static void refresh_process_list() {
    ProcCandidate tmp[256];
    const size_t n = proc_list_all(tmp, 256);
    g_procCount = 0;
    const std::string needle = g_search;
    for (size_t i = 0; i < n && g_procCount < 256; ++i) {
        if (g_filterIl2CppOnly && !tmp[i].hasIl2Cpp) continue;
        if (!needle.empty()) {
            std::string cmd = tmp[i].cmdline;
            if (cmd.find(needle) == std::string::npos) continue;
        }
        g_procs[g_procCount++] = tmp[i];
    }
    g_selected = -1;
    for (size_t i = 0; i < g_procCount; ++i) {
        if (g_procs[i].pid == g_selectedPid) {
            g_selected = (int)i;
            break;
        }
    }
    ui_log("[proc] listed %zu (filter il2cpp=%s)", g_procCount, g_filterIl2CppOnly ? "on" : "off");
}

static void run_dump_thread(pid_t pid, std::string cmdline, std::string outPath) {
    g_dumpRunning.store(true);
    g_dumpProgress.store(0.f);
    std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Dumping PID %d...", (int)pid);
    ui_log("[dump] start pid=%d", (int)pid);
    ui_log("[dump] target: %s", cmdline.c_str());

    RemoteIl2CppExecutor ex{};
    char err[256] = {};
    if (!ex.open(pid, err, sizeof(err))) {
        ui_log("[dump] ERROR open: %s", err);
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Failed: %s", err);
        g_dumpRunning.store(false);
        return;
    }
    ui_log("[dump] lib=%s base=0x%llx", ex.info.libPath, (unsigned long long)ex.info.base);
    if (ex.info.note[0]) ui_log("[dump] %s", ex.info.note);

    const bool ok = ex.run_dump(
        outPath, cmdline,
        [](const char *msg) { ui_log("%s", msg); },
        [](const DumpProgress &p) { g_dumpProgress.store(p.progress); });

    ex.close();
    if (ok) {
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Done → %s", outPath.c_str());
        ui_log("[dump] output: %s", outPath.c_str());
    } else {
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Dump failed — see log");
    }
    g_dumpProgress.store(ok ? 1.f : 0.f);
    g_dumpRunning.store(false);
}

static void draw_ui() {
    if (!g_showMenu) return;

    ImGui::SetNextWindowSize({400, 520}, ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowBgAlpha(0.95f);
    if (ImGui::Begin("IL2CPP External Dump", &g_showMenu, ImGuiWindowFlags_None)) {
        ImGui::TextColored(ImVec4(0.4f, 0.85f, 1.f, 1.f), "Universal dump.cs");
        ImGui::TextDisabled("Domain resolve (mlbb-esp) + conRent dump format");
        ImGui::Spacing();

        if (ImGui::Button("Refresh processes", ImVec2(-1, 0))) refresh_process_list();
        ImGui::Checkbox("Show IL2CPP processes only", &g_filterIl2CppOnly);
        ImGui::SetNextItemWidth(-1);
        ImGui::InputTextWithHint("##search", "Filter cmdline...", g_search, sizeof(g_search));
        if (ImGui::IsItemDeactivatedAfterEdit()) refresh_process_list();

        ImGui::BeginChild("plist", ImVec2(0, 160), true);
        for (size_t i = 0; i < g_procCount; ++i) {
            char label[320];
            std::snprintf(label, sizeof(label), "%s  [%d]%s", g_procs[i].cmdline, (int)g_procs[i].pid,
                          g_procs[i].hasIl2Cpp ? "  *il2cpp*" : "");
            if (ImGui::Selectable(label, g_selected == (int)i)) {
                g_selected = (int)i;
                g_selectedPid = g_procs[i].pid;
            }
        }
        if (g_procCount == 0)
            ImGui::TextDisabled("No processes — tap Refresh (root helps read other apps)");
        ImGui::EndChild();

        const bool canDump = g_selected >= 0 && g_selected < (int)g_procCount && !g_dumpRunning.load();
        if (g_selected >= 0 && g_selected < (int)g_procCount) {
            ImGui::Text("Selected PID: %d", (int)g_procs[g_selected].pid);
            if (!proc_probe_read(g_procs[g_selected].pid))
                ImGui::TextColored(ImVec4(1.f, 0.45f, 0.35f, 1.f), "Cannot read memory — need root / same user");
        }

        ImGui::Spacing();
        if (g_dumpRunning.load()) {
            ImGui::ProgressBar(g_dumpProgress.load(), ImVec2(-1, 0));
            ImGui::TextWrapped("%s", g_dumpStatus);
        } else {
            ImGui::TextWrapped("%s", g_dumpStatus);
        }

        ImGui::BeginDisabled(!canDump);
        if (ImGui::Button("Dump dump.cs", ImVec2(-1, 44))) {
            const auto &p = g_procs[g_selected];
            const std::string out = g_filesDir + "/dump.cs";
            std::thread(run_dump_thread, p.pid, std::string(p.cmdline), out).detach();
        }
        ImGui::EndDisabled();

        ImGui::SeparatorText("Log");
        ImGui::Checkbox("Auto-scroll", &g_logScrollBottom);
        if (ImGui::Button("Copy log")) {
            static char logCopy[65536];
            ui_log_copy_all(logCopy, sizeof(logCopy));
            if (android_copy_to_clipboard(logCopy)) ui_log("[ui] log copied");
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear")) ui_log_clear();

        static char logText[65536];
        ui_log_copy_all(logText, sizeof(logText));
        ImGui::BeginChild("logs", {0, 140}, true);
        ImGui::TextUnformatted(logText);
        if (g_logScrollBottom) ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();
    }
    ImGui::End();
}

void ui_pipeline_idle() {
    refresh_process_list();
    ui_log("[app] IL2CPP external dumper ready");
    ui_log("[app] output dir: %s", g_filesDir.c_str());
}

extern "C" void ui_set_files_dir(const char *path) {
    if (path && path[0]) g_filesDir = path;
}

static bool init_imgui_backends() {
    if (!ImGui::GetCurrentContext()) {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;
        ImGui::StyleColorsDark();
        apply_menu_style();
        io.Fonts->AddFontDefault();
        ImGui::GetStyle().TouchExtraPadding = ImVec2(4.f, 4.f);
    }
    if (g_imguiBackend) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplAndroid_Shutdown();
        g_imguiBackend = false;
    }
    ImGui_ImplAndroid_Init(nullptr);
    if (!ImGui_ImplOpenGL3_Init(g_glslVersion)) return false;
    g_imguiBackend = true;
    return true;
}

void ui_set_display_size(int width, int height) {
    if (width > 0 && height > 0) {
        g_displayW = width;
        g_displayH = height;
    }
}

void ui_gl_surface_created() {
    std::lock_guard<std::mutex> lock(g_glMu);
    g_glReady = init_imgui_backends();
}

void ui_gl_surface_changed(int width, int height) {
    std::lock_guard<std::mutex> lock(g_glMu);
    g_width = width > 0 ? width : 1;
    g_height = height > 0 ? height : 1;
}

void ui_gl_surface_destroyed() {
    std::lock_guard<std::mutex> lock(g_glMu);
    if (g_imguiBackend) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplAndroid_Shutdown();
        g_imguiBackend = false;
    }
    if (ImGui::GetCurrentContext()) ImGui::DestroyContext();
    g_glReady = false;
}

void ui_gl_draw_frame() {
    std::lock_guard<std::mutex> lock(g_glMu);
    if (!g_glReady || !g_imguiBackend) return;
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplAndroid_NewFrame(g_width, g_height);
    ImGui::NewFrame();
    draw_ui();
    ImGui::Render();
    ImDrawData *dd = ImGui::GetDrawData();
    if (!dd) return;
    glViewport(0, 0, g_width, g_height);
    glClearColor(0.f, 0.f, 0.f, 0.f);
    glClear(GL_COLOR_BUFFER_BIT);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    ImGui_ImplOpenGL3_RenderDrawData(dd);
}

void ui_touch(int action, float x, float y) {
    ImGuiIO &io = ImGui::GetIO();
    io.MousePos = ImVec2(x, y);
    if (action == 0)
        io.MouseDown[0] = true;
    else if (action == 1)
        io.MouseDown[0] = false;
}

void ui_open_menu() { g_showMenu = true; }
void ui_toggle_menu() { g_showMenu = !g_showMenu; }
bool ui_menu_interactive() { return g_showMenu; }
