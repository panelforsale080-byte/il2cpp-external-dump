#include "ui_core.hpp"
#include "proc.hpp"
#include "ui_log.hpp"
#include "clip_android.hpp"
#include "il2cpp_remote.hpp"
#include "path_util.hpp"

#include <android/input.h>
#include <GLES2/gl2.h>
#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>

#include "imgui.h"
#include "imgui_impl_android.h"
#include "imgui_impl_opengl3.h"

static int g_width = 0, g_height = 0;
ImVec2 initialScreenSize;
ImVec2 &ui_initial_screen_size() { return initialScreenSize; }

static bool g_glReady = false;
static bool g_imguiBackend = false;
static std::mutex g_glMu;
static const char *g_glslVersion = "#version 100";

static bool g_logScrollBottom = true;
static bool g_filterIl2CppOnly = false;
static char g_search[128] = {};

static ProcCandidate g_procs[256];
static size_t g_procCount = 0;
static int g_selected = -1;
static pid_t g_selectedPid = 0;
static int g_manualPid = 0;
static bool g_useManualPid = false;

static std::atomic<bool> g_dumpRunning{false};
static std::atomic<float> g_dumpProgress{0.f};
static char g_dumpStatus[256] = "Select a process and tap Generate dump.cs";


static void apply_theme() {
    ImGuiStyle &s = ImGui::GetStyle();
    ImVec4 *c = s.Colors;
    s.WindowRounding = 0.f;
    s.ChildRounding = 14.f;
    s.FrameRounding = 10.f;
    s.GrabRounding = 8.f;
    s.ScrollbarRounding = 10.f;
    s.WindowPadding = ImVec2(18.f, 16.f);
    s.FramePadding = ImVec2(12.f, 10.f);
    s.ItemSpacing = ImVec2(12.f, 10.f);
    s.ItemInnerSpacing = ImVec2(8.f, 6.f);
    s.WindowBorderSize = 0.f;
    s.ChildBorderSize = 1.f;

    const ImVec4 bg = ImVec4(0.05f, 0.06f, 0.09f, 1.f);
    const ImVec4 panel = ImVec4(0.08f, 0.10f, 0.14f, 1.f);
    const ImVec4 accent = ImVec4(0.22f, 0.55f, 0.98f, 1.f);
    const ImVec4 accentDim = ImVec4(0.14f, 0.38f, 0.72f, 1.f);

    c[ImGuiCol_Text] = ImVec4(0.92f, 0.94f, 0.97f, 1.f);
    c[ImGuiCol_TextDisabled] = ImVec4(0.45f, 0.50f, 0.58f, 1.f);
    c[ImGuiCol_WindowBg] = bg;
    c[ImGuiCol_ChildBg] = panel;
    c[ImGuiCol_PopupBg] = ImVec4(0.07f, 0.09f, 0.12f, 0.98f);
    c[ImGuiCol_Border] = ImVec4(0.18f, 0.24f, 0.34f, 0.6f);
    c[ImGuiCol_FrameBg] = ImVec4(0.10f, 0.12f, 0.17f, 1.f);
    c[ImGuiCol_FrameBgHovered] = ImVec4(0.13f, 0.16f, 0.22f, 1.f);
    c[ImGuiCol_FrameBgActive] = ImVec4(0.15f, 0.19f, 0.26f, 1.f);
    c[ImGuiCol_TitleBg] = bg;
    c[ImGuiCol_TitleBgActive] = bg;
    c[ImGuiCol_Button] = accentDim;
    c[ImGuiCol_ButtonHovered] = accent;
    c[ImGuiCol_ButtonActive] = ImVec4(0.12f, 0.32f, 0.62f, 1.f);
    c[ImGuiCol_Header] = ImVec4(0.14f, 0.32f, 0.58f, 0.45f);
    c[ImGuiCol_HeaderHovered] = ImVec4(0.18f, 0.42f, 0.75f, 0.65f);
    c[ImGuiCol_HeaderActive] = ImVec4(0.20f, 0.48f, 0.85f, 0.85f);
    c[ImGuiCol_CheckMark] = ImVec4(0.45f, 0.82f, 1.f, 1.f);
    c[ImGuiCol_SliderGrab] = accent;
    c[ImGuiCol_SliderGrabActive] = ImVec4(0.35f, 0.65f, 1.f, 1.f);
    c[ImGuiCol_Separator] = ImVec4(0.22f, 0.30f, 0.42f, 0.5f);
}

static void refresh_process_list() {
    ProcCandidate tmp[512];
    const size_t n = proc_list_all(tmp, 512);
    size_t il2Count = 0;
    for (size_t i = 0; i < n; ++i)
        if (tmp[i].hasIl2Cpp) ++il2Count;

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
    ui_log("[proc] scanned %zu PIDs, il2cpp-tagged %zu, showing %zu (filter=%s)",
           n, il2Count, g_procCount, g_filterIl2CppOnly ? "IL2CPP only" : "all");
    if (g_procCount == 0) {
        if (g_filterIl2CppOnly && il2Count == 0)
            ui_log("[proc] walang IL2CPP sa maps — i-off ang 'IL2CPP only' o gamit root + buksan game");
        else if (n == 0)
            ui_log("[proc] hindi mabasa ang /proc — kailangan normal Android app context");
        else
            ui_log("[proc] walang match sa search/filter — i-clear search o i-refresh");
    }
}

static void run_dump_thread(pid_t pid, std::string cmdline, std::string outPath) {
    g_dumpRunning.store(true);
    g_dumpProgress.store(0.f);
    std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Dumping PID %d…", (int)pid);
    ui_log("[dump] start pid=%d", (int)pid);
    ui_log("[dump] %s", cmdline.c_str());
    ui_log("[dump] attach + resolve IL2CPP…");

    RemoteIl2CppExecutor ex{};
    char err[256] = {};
    if (!ex.open(pid, err, sizeof(err))) {
        ui_log("[dump] ERROR: %s", err);
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Failed: %s", err);
        g_dumpRunning.store(false);
        return;
    }
    ui_log("[dump] lib=%s", ex.info.libPath);
    ui_log("[dump] base=0x%llx", (unsigned long long)ex.info.base);
    if (ex.info.note[0]) ui_log("[dump] %s", ex.info.note);

    const bool ok = ex.run_dump(
        outPath, cmdline,
        [](const char *msg) { ui_log("%s", msg); },
        [](const DumpProgress &p) { g_dumpProgress.store(p.progress); });

    ex.close();
    if (ok) {
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Saved: %s", outPath.c_str());
        ui_log("[dump] OK → %s", outPath.c_str());
    } else {
        std::snprintf(g_dumpStatus, sizeof(g_dumpStatus), "Dump failed — check log");
    }
    g_dumpProgress.store(ok ? 1.f : 0.f);
    g_dumpRunning.store(false);
}

static void draw_header() {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.07f, 0.11f, 0.20f, 1.f));
    ImGui::BeginChild("hdr", ImVec2(-1, 72), true);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 4.f);
    ImGui::TextColored(ImVec4(0.55f, 0.82f, 1.f, 1.f), "IL2CPP DUMPER");
    ImGui::SameLine();
    ImGui::TextDisabled("  external");
    ImGui::TextWrapped("Universal dump.cs - any IL2CPP game - conRent format - root recommended");
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static void draw_ui() {
    const ImVec2 display = ImGui::GetIO().DisplaySize;
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(display);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16.f, 12.f));
    ImGui::Begin("##root", nullptr,
                 ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);

    draw_header();
    ImGui::Spacing();

    ImGui::BeginChild("main", ImVec2(-1, -1), false);
    if (ImGui::Button("Refresh", ImVec2(100.f, 0.f))) refresh_process_list();
    ImGui::SameLine();
    if (ImGui::Checkbox("IL2CPP only", &g_filterIl2CppOnly)) refresh_process_list();
    ImGui::SameLine();
    ImGui::SetNextItemWidth(-1);
    ImGui::InputTextWithHint("##q", "Search package / process…", g_search, sizeof(g_search));
    if (ImGui::IsItemDeactivatedAfterEdit()) refresh_process_list();

    const float listH = display.y * 0.30f;
    ImGui::BeginChild("plist", ImVec2(-1, listH), true);

    for (size_t row = 0; row < g_procCount; ++row) {
        const auto &p = g_procs[row];
        const bool sel = !g_useManualPid && g_selected == (int)row;
        ImGui::PushID((int)p.pid);

        const char *name = p.cmdline[0] ? p.cmdline : proc_comm_fallback(p.pid);
        char rowLabel[400];
        std::snprintf(rowLabel, sizeof(rowLabel), "%d  |  %s%s", (int)p.pid, name,
                      p.hasIl2Cpp ? "  (IL2CPP)" : "");

        if (sel) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.42f, 0.72f, 1.f));
        else if (p.hasIl2Cpp) ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.10f, 0.28f, 0.22f, 1.f));
        else ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.14f, 0.20f, 1.f));

        if (ImGui::Button(rowLabel, ImVec2(-1, 42.f))) {
            g_useManualPid = false;
            g_selected = (int)row;
            g_selectedPid = p.pid;
        }
        ImGui::PopStyleColor();
        ImGui::PopID();
    }

    if (g_procCount == 0) {
        ImGui::TextColored(ImVec4(1.f, 0.55f, 0.4f, 1.f), "Walang process sa listahan");
        ImGui::TextWrapped(
            "GSpace/virtual: i-install dumper at game sa same space. "
            "Root = makita lahat ng app sa device.");
    }
    ImGui::EndChild();

    ImGui::SetNextItemWidth(120.f);
    ImGui::InputInt("Manual PID", &g_manualPid);
    ImGui::SameLine();
    if (ImGui::Button("Use PID")) {
        if (g_manualPid > 0 && proc_alive((pid_t)g_manualPid)) {
            g_useManualPid = true;
            g_selected = -1;
            g_selectedPid = (pid_t)g_manualPid;
            ui_log("[proc] manual PID %d", g_manualPid);
        } else {
            ui_log("[proc] invalid PID %d", g_manualPid);
        }
    }

    ImGui::Spacing();
    ImGui::BeginChild("status", ImVec2(-1, 88), true);
    if (g_selectedPid > 0 && (g_useManualPid || (g_selected >= 0 && g_selected < (int)g_procCount))) {
        ImGui::Text("Target PID %d%s", (int)g_selectedPid, g_useManualPid ? " (manual)" : "");
        if (!g_useManualPid && g_selected >= 0 && g_selected < (int)g_procCount)
            ImGui::TextWrapped("%s", g_procs[g_selected].cmdline);
        if (!proc_probe_read(g_selectedPid))
            ImGui::TextColored(ImVec4(1.f, 0.42f, 0.38f, 1.f), "Cannot read memory — root / same virtual app");
    } else {
        ImGui::TextDisabled("No process selected");
    }
    if (g_dumpRunning.load()) {
        ImGui::ProgressBar(g_dumpProgress.load(), ImVec2(-1, 22.f));
    }
    ImGui::TextWrapped("%s", g_dumpStatus);
    ImGui::EndChild();

    const bool canDump = g_selectedPid > 0 && !g_dumpRunning.load();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.18f, 0.52f, 0.95f, canDump ? 1.f : 0.35f));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(16.f, 14.f));
    ImGui::BeginDisabled(!canDump);
    if (ImGui::Button("Generate dump.cs", ImVec2(-1, 0.f))) {
        char cmd[280] = {};
        if (!g_useManualPid && g_selected >= 0 && g_selected < (int)g_procCount)
            std::snprintf(cmd, sizeof(cmd), "%s", g_procs[g_selected].cmdline);
        else
            std::snprintf(cmd, sizeof(cmd), "manual pid %d", (int)g_selectedPid);
        const std::string out = dump_output_path(cmd, g_selectedPid);
        std::thread(run_dump_thread, g_selectedPid, std::string(cmd), out).detach();
    }
    ImGui::EndDisabled();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor();

    ImGui::TextDisabled("Save: %s/<package>_dump.cs", ui_sdcard_dir().c_str());

    ImGui::Spacing();
    ImGui::Separator();
    if (ImGui::Button("Copy log", ImVec2(90.f, 0.f))) {
        static char logCopy[65536];
        ui_log_copy_all(logCopy, sizeof(logCopy));
        if (android_copy_to_clipboard(logCopy)) ui_log("[ui] log copied");
    }
    ImGui::SameLine();
    if (ImGui::Button("Clear", ImVec2(70.f, 0.f))) ui_log_clear();
    ImGui::SameLine();
    ImGui::Checkbox("Auto-scroll log", &g_logScrollBottom);

    static char logText[65536];
    ui_log_copy_all(logText, sizeof(logText));
    const float logH = ImGui::GetContentRegionAvail().y;
    ImGui::BeginChild("log", ImVec2(-1, logH > 80.f ? logH : 80.f), true);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.72f, 0.78f, 0.86f, 1.f));
    ImGui::TextUnformatted(logText);
    ImGui::PopStyleColor();
    if (g_logScrollBottom) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    ImGui::EndChild();
    ImGui::End();
    ImGui::PopStyleVar();
}

void ui_pipeline_idle() {
    refresh_process_list();
    ui_log("[app] IL2CPP Dumper ready (standalone)");
    ui_log("[app] sdcard: %s", ui_sdcard_dir().c_str());
}

static bool init_imgui_backends() {
    if (!ImGui::GetCurrentContext()) {
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO &io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.ConfigFlags |= ImGuiConfigFlags_IsTouchScreen;
        io.FontGlobalScale = 1.08f;
        apply_theme();
        io.Fonts->AddFontDefault();
        ImGui::GetStyle().TouchExtraPadding = ImVec2(6.f, 6.f);
        initialScreenSize = io.DisplaySize;
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

void ui_gl_surface_created() {
    std::lock_guard<std::mutex> lock(g_glMu);
    g_glReady = init_imgui_backends();
}

void ui_gl_surface_changed(int width, int height) {
    std::lock_guard<std::mutex> lock(g_glMu);
    g_width = width > 0 ? width : 1;
    g_height = height > 0 ? height : 1;
    initialScreenSize = ImVec2((float)g_width, (float)g_height);
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
    glClearColor(0.05f, 0.06f, 0.09f, 1.f);
    glClear(GL_COLOR_BUFFER_BIT);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    ImGui_ImplOpenGL3_RenderDrawData(dd);
}

void ui_touch(int action, float x, float y) {
    ImGuiIO &io = ImGui::GetIO();
    io.AddMousePosEvent(x, y);
    if (action == AMOTION_EVENT_ACTION_DOWN || action == 0)
        io.AddMouseButtonEvent(0, true);
    else if (action == AMOTION_EVENT_ACTION_UP || action == 1)
        io.AddMouseButtonEvent(0, false);
}
