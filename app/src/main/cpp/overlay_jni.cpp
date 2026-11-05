#include "ui_core.hpp"
#include "clip_android.hpp"
#include "path_util.hpp"
#include <jni.h>

static JavaVM *g_vm = nullptr;

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *) {
    g_vm = vm;
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeInit(JNIEnv *, jclass) {
    ui_pipeline_idle();
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeSetContext(JNIEnv *env, jclass, jobject ctx) {
    android_clip_set_context(g_vm, ctx);
    jclass ctxCls = env->GetObjectClass(ctx);
    jmethodID getPkg = env->GetMethodID(ctxCls, "getPackageName", "()Ljava/lang/String;");
    if (getPkg) {
        jstring pkg = (jstring)env->CallObjectMethod(ctx, getPkg);
        if (pkg) {
            const char *utf = env->GetStringUTFChars(pkg, nullptr);
            if (utf) {
                ui_set_own_package(utf);
                env->ReleaseStringUTFChars(pkg, utf);
            }
        }
    }
    jmethodID getFilesDir = env->GetMethodID(ctxCls, "getFilesDir", "()Ljava/io/File;");
    jobject file = env->CallObjectMethod(ctx, getFilesDir);
    if (file) {
        jclass fileCls = env->GetObjectClass(file);
        jmethodID getPath = env->GetMethodID(fileCls, "getAbsolutePath", "()Ljava/lang/String;");
        jstring path = (jstring)env->CallObjectMethod(file, getPath);
        if (path) {
            const char *utf = env->GetStringUTFChars(path, nullptr);
            ui_set_files_dir(utf);
            env->ReleaseStringUTFChars(path, utf);
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeSetSdcardDir(JNIEnv *env, jclass, jstring path) {
    if (!path) return;
    const char *utf = env->GetStringUTFChars(path, nullptr);
    if (utf) {
        ui_set_sdcard_dir(utf);
        env->ReleaseStringUTFChars(path, utf);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeGlSurfaceCreated(JNIEnv *, jclass) {
    ui_gl_surface_created();
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeGlSurfaceChanged(JNIEnv *, jclass, jint w, jint h) {
    ui_gl_surface_changed((int)w, (int)h);
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeGlSurfaceDestroyed(JNIEnv *, jclass) {
    ui_gl_surface_destroyed();
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeGlDrawFrame(JNIEnv *, jclass) {
    ui_gl_draw_frame();
}

extern "C" JNIEXPORT void JNICALL
Java_com_il2cpp_externaldump_NativeBridge_nativeTouch(JNIEnv *, jclass, jint action, jfloat x, jfloat y) {
    ui_touch((int)action, (float)x, (float)y);
}
