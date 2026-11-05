cmake_minimum_required(VERSION 3.22.1)
project(Il2Dump)

set(IMGUI_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui)

add_library(Il2Dump SHARED
    ui_core.cpp
    overlay_jni.cpp
    proc.cpp
    mem.cpp
    remote_call.cpp
    ui_log.cpp
    remote_il2cpp.cpp
    remote_elf.cpp
    clip_android.cpp
    il2cpp_remote.cpp
    dump_cs_engine.cpp
    path_util.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_impl_android.cpp
    ${IMGUI_DIR}/imgui_impl_opengl3.cpp)

target_include_directories(Il2Dump PRIVATE ${IMGUI_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/Il2cpp)

target_compile_definitions(Il2Dump PRIVATE
    IMGUI_IMPL_OPENGL_ES2
    GLES_SILENCE_DEPRECATION)

find_library(log-lib log)
find_library(android-lib android)
find_library(EGL-lib EGL)
find_library(GLESv2-lib GLESv2)

target_link_libraries(Il2Dump
    ${log-lib}
    ${android-lib}
    ${EGL-lib}
    ${GLESv2-lib})
