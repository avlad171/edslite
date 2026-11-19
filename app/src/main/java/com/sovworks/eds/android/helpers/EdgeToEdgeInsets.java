package com.sovworks.eds.android.helpers;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.view.View;

import androidx.annotation.NonNull;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/**
 * Android 15+ draws every app edge to edge, and apps targeting SDK 36+ can't opt out. EDS's
 * layouts predate that: content started under the status bar and the (framework) action bar,
 * hiding e.g. the first drawer entries. This pads each activity's content view by the system
 * bars, display cutout and keyboard. The framework action bar's overlay layout already adds the
 * action bar height to the top inset it hands to the content. Floating (dialog) windows are left
 * alone.
 */
public final class EdgeToEdgeInsets implements Application.ActivityLifecycleCallbacks
{
    public static void install(Application app)
    {
        app.registerActivityLifecycleCallbacks(new EdgeToEdgeInsets());
    }

    @Override
    public void onActivityPostCreated(@NonNull Activity activity, Bundle savedInstanceState)
    {
        if (activity.getWindow() == null || activity.getWindow().isFloating())
            return;
        View content = activity.findViewById(android.R.id.content);
        if (content == null)
            return;
        ViewCompat.setOnApplyWindowInsetsListener(content, (v, insets) -> {
            Insets bars = insets.getInsets(WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.displayCutout());
            Insets ime = insets.getInsets(WindowInsetsCompat.Type.ime());
            v.setPadding(bars.left, bars.top, bars.right, Math.max(bars.bottom, ime.bottom));
            return WindowInsetsCompat.CONSUMED;
        });
        ViewCompat.requestApplyInsets(content);
    }

    @Override public void onActivityCreated(@NonNull Activity a, Bundle b) { }
    @Override public void onActivityStarted(@NonNull Activity a) { }
    @Override public void onActivityResumed(@NonNull Activity a) { }
    @Override public void onActivityPaused(@NonNull Activity a) { }
    @Override public void onActivityStopped(@NonNull Activity a) { }
    @Override public void onActivitySaveInstanceState(@NonNull Activity a, @NonNull Bundle b) { }
    @Override public void onActivityDestroyed(@NonNull Activity a) { }
}
