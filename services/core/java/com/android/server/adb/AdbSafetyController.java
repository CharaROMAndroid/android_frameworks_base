/*
 * Copyright (C) 2026 CharaROM
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.adb;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningTaskInfo;
import android.app.ActivityTaskManager;
import android.app.ActivityTaskManager.RootTaskInfo;
import android.app.TaskStackListener;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.ContentObserver;
import android.os.Binder;
import android.os.Handler;
import android.os.RemoteException;
import android.os.UserHandle;
import android.os.UserManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Slog;

import com.android.server.FgThread;
import com.android.server.LocalServices;

/** System-owned ADB safety policy. No app-supplied foreground identity is accepted. */
public final class AdbSafetyController {
    private static final String TAG = "AdbSafetyController";
    public static final String AUTO_DISABLE_APPS = "adb_auto_disable_apps";

    /** Local-only USB bridge; implementations must validate lock/restrictions on the USB handler. */
    public interface UsbFunctions {
        void selectAfterAdbShutdown(int foregroundUserId);
    }

    private final Context mContext;
    private final AdbService mService;
    private final Handler mHandler = FgThread.getHandler();
    private final Runnable mCheckForeground = this::checkForeground;

    AdbSafetyController(Context context, AdbService service) {
        mContext = context;
        mService = service;
        LocalServices.addService(AdbSafetyController.class, this);
    }

    /**
     * Disable both real ADB transports, without restoring either automatically.
     * Called only inside system_server.
     * Work is serialized on FgThread; completion does not promise synchronous native teardown.
     */
    public static void disableDebugging(Context context) {
        final AdbSafetyController controller =
                LocalServices.getService(AdbSafetyController.class);
        if (controller == null) {
            Slog.w(TAG, "ADB service not ready for safety shutdown");
            return;
        }
        controller.mHandler.post(() -> {
            final long token = Binder.clearCallingIdentity();
            try {
                controller.mService.disableDebuggingForSafety();
            } finally {
                Binder.restoreCallingIdentity(token);
            }
        });
    }

    void start() {
        mContext.getContentResolver().registerContentObserver(
                Settings.Secure.getUriFor(AUTO_DISABLE_APPS), false,
                new ContentObserver(mHandler) {
                    @Override
                    public void onChange(boolean selfChange) {
                        scheduleForegroundCheck();
                    }
                }, UserHandle.USER_ALL);
        final ContentObserver debugObserver = new ContentObserver(mHandler) {
            @Override
            public void onChange(boolean selfChange) {
                scheduleForegroundCheck();
            }
        };
        mContext.getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.ADB_ENABLED), false, debugObserver);
        mContext.getContentResolver().registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.ADB_WIFI_ENABLED), false, debugObserver);
        mContext.registerReceiverAsUser(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                scheduleForegroundCheck();
            }
        }, UserHandle.ALL, new IntentFilter(Intent.ACTION_USER_SWITCHED), null, mHandler);
        try {
            ActivityTaskManager.getService().registerTaskStackListener(new TaskStackListener() {
                @Override
                public void onTaskStackChanged() {
                    scheduleForegroundCheck();
                }

                @Override
                public void onTaskMovedToFront(RunningTaskInfo taskInfo) {
                    scheduleForegroundCheck();
                }

                @Override
                public void onTaskFocusChanged(int taskId, boolean focused) {
                    scheduleForegroundCheck();
                }
            });
        } catch (RemoteException e) {
            Slog.e(TAG, "Cannot observe focused applications", e);
        }
        scheduleForegroundCheck();
    }

    private void scheduleForegroundCheck() {
        mHandler.removeCallbacks(mCheckForeground);
        mHandler.post(mCheckForeground);
    }

    private void checkForeground() {
        final long token = Binder.clearCallingIdentity();
        try {
            if (Settings.Global.getInt(mContext.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) == 0
                    && Settings.Global.getInt(mContext.getContentResolver(),
                    Settings.Global.ADB_WIFI_ENABLED, 0) == 0) return;
            final RootTaskInfo task = ActivityTaskManager.getService().getFocusedRootTaskInfo();
            if (task == null || !task.isFocused || !task.isVisible || !task.isRunning
                    || task.topActivity == null
                    || task.topActivityInfo == null
                    || task.topActivityInfo.applicationInfo == null) return;
            // Root tasks can contain a profile's child task. Use the actual top activity's UID.
            final int userId = UserHandle.getUserId(task.topActivityInfo.applicationInfo.uid);
            final int currentUser = ActivityManager.getCurrentUser();
            final UserManager users = mContext.getSystemService(UserManager.class);
            boolean activeProfile = false;
            for (int profileId : users.getEnabledProfileIds(currentUser)) {
                if (profileId == userId) activeProfile = true;
            }
            if (!activeProfile) return;
            final String packageName = task.topActivity.getPackageName();
            if (!packageName.equals(task.topActivityInfo.packageName)) return;
            final String configured = Settings.Secure.getStringForUser(
                    mContext.getContentResolver(), AUTO_DISABLE_APPS, userId);
            if (!matches(configured, packageName)) return;
            // Execute on this handler, not another asynchronous app-originated callback.
            mService.disableDebuggingForSafety();
        } catch (RemoteException | RuntimeException e) {
            Slog.w(TAG, "Cannot evaluate foreground ADB safety policy", e);
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    static boolean matches(String configured, String packageName) {
        if (TextUtils.isEmpty(configured) || TextUtils.isEmpty(packageName)) return false;
        for (String selected : configured.split(",")) {
            if (packageName.equals(selected.trim())) return true;
        }
        return false;
    }
}
