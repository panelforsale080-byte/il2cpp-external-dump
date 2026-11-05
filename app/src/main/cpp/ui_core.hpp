#pragma once
#include "imgui.h"

ImVec2 &ui_initial_screen_size();

void ui_pipeline_idle();

void ui_gl_surface_created();
void ui_gl_surface_changed(int width, int height);
void ui_gl_surface_destroyed();
void ui_gl_draw_frame();

void ui_touch(int action, float x, float y);
