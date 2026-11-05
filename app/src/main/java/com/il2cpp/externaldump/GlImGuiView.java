package com.il2cpp.externaldump;

import android.content.Context;
import android.opengl.GLSurfaceView;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;

import javax.microedition.khronos.egl.EGLConfig;
import javax.microedition.khronos.opengles.GL10;

public class GlImGuiView extends GLSurfaceView implements GLSurfaceView.Renderer {
    private static final String TAG = "Il2DumpGl";
    private volatile boolean surfaceReady = false;
    private volatile boolean nativeInited = false;

    public GlImGuiView(Context context) {
        super(context);
        initGl();
    }

    public GlImGuiView(Context context, AttributeSet attrs) {
        super(context, attrs);
        initGl();
    }

    private void initGl() {
        setEGLContextClientVersion(2);
        setEGLConfigChooser(8, 8, 8, 8, 16, 0);
        setPreserveEGLContextOnPause(true);
        setRenderer(this);
        setRenderMode(RENDERMODE_WHEN_DIRTY);
    }

    @Override
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        try {
            NativeBridge.nativeGlSurfaceCreated();
        } catch (Throwable t) {
            Log.e(TAG, "surfaceCreated", t);
            surfaceReady = false;
        }
    }

    @Override
    public void onSurfaceChanged(GL10 gl, int width, int height) {
        if (width <= 0 || height <= 0) return;
        try {
            NativeBridge.nativeGlSurfaceChanged(width, height);
            if (!nativeInited) {
                NativeBridge.nativeInit();
                nativeInited = true;
            }
            surfaceReady = true;
            setRenderMode(RENDERMODE_CONTINUOUSLY);
            requestRender();
        } catch (Throwable t) {
            Log.e(TAG, "surfaceChanged", t);
            surfaceReady = false;
        }
    }

    @Override
    public void onDrawFrame(GL10 gl) {
        if (!surfaceReady) return;
        try {
            NativeBridge.nativeGlDrawFrame();
        } catch (Throwable t) {
            Log.e(TAG, "drawFrame", t);
        }
    }

    public void releaseGl() {
        surfaceReady = false;
        nativeInited = false;
        queueEvent(() -> {
            try {
                NativeBridge.nativeGlSurfaceDestroyed();
            } catch (Throwable t) {
                Log.e(TAG, "destroy", t);
            }
        });
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        if (!surfaceReady) return super.onTouchEvent(event);
        final int action = event.getActionMasked();
        try {
            NativeBridge.nativeTouch(action, event.getX(), event.getY());
            requestRender();
        } catch (Throwable t) {
            Log.e(TAG, "touch", t);
            return false;
        }
        return true;
    }
}
