package com.il2cpp.externaldump;

public final class NativeBridge {
    static {
        System.loadLibrary("Il2Dump");
    }

    public static native void nativeInit();
    public static native void nativeSetContext(Object context);
    public static native void nativeGlSurfaceCreated();
    public static native void nativeGlSurfaceChanged(int w, int h);
    public static native void nativeGlSurfaceDestroyed();
    public static native void nativeGlDrawFrame();
    public static native void nativeTouch(int action, float x, float y);
}
