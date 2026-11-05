package com.il2cpp.externaldump;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.view.View;
import android.view.WindowManager;

import java.io.File;

/** Full-screen native ImGui app — no overlay. */
public class DumpActivity extends Activity {
    private static final int REQ_STORAGE = 2001;
    private GlImGuiView glView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().getDecorView().setSystemUiVisibility(
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN);

        configureStoragePaths();
        NativeBridge.nativeSetContext(getApplicationContext());
        glView = new GlImGuiView(this);
        setContentView(glView);
    }

    private void configureStoragePaths() {
        if (Build.VERSION.SDK_INT <= Build.VERSION_CODES.S_V2) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                requestPermissions(
                        new String[]{
                                Manifest.permission.WRITE_EXTERNAL_STORAGE,
                                Manifest.permission.READ_EXTERNAL_STORAGE
                        },
                        REQ_STORAGE);
            }
        }
        File download = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        if (download != null) {
            if (!download.exists()) download.mkdirs();
            NativeBridge.nativeSetSdcardDir(download.getAbsolutePath());
        } else {
            NativeBridge.nativeSetSdcardDir("/storage/emulated/0/Download");
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (glView != null) glView.onResume();
    }

    @Override
    protected void onPause() {
        if (glView != null) glView.onPause();
        super.onPause();
    }
}
