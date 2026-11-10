/*
 * Copyright (C) 2026 CharaROM
 * SPDX-License-Identifier: Apache-2.0
 */
package android.os;

import android.content.Context;
import android.content.Intent;
import android.hardware.usb.UsbManager;
import android.net.Uri;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;

/**
 * Process-local presentation policy. Does not disable ADB or change debugger permissions.
 * @hide
 */
public final class AdbStatePrivacy {
    public static final String PACKAGES = "adb_state_hidden_packages";
    public static final String CALL_POLICY = "GET_adb_state_privacy";
    private static final String TAG = "AdbStatePrivacy";

    private static volatile boolean sHideInProcess;

    private AdbStatePrivacy() {}

    /** Match a UID's packages, never a caller-supplied package/UID. */
    public static boolean matches(String configured, String[] packages) {
        if (TextUtils.isEmpty(configured) || packages == null) return false;
        for (String selected : configured.split(",")) {
            if (selected.isEmpty()) continue;
            for (String pkg : packages) {
                if (selected.equals(pkg)) return true;
            }
        }
        return false;
    }

    /** Called only from trusted services with the actual recipient/caller UID. */
    public static boolean shouldHideUid(Context context, int uid) {
        if (UserHandle.getAppId(uid) < Process.FIRST_APPLICATION_UID
                || Process.isIsolated(uid)) return false;
        final long token = Binder.clearCallingIdentity();
        try {
            String config = Settings.Secure.getStringForUser(context.getContentResolver(),
                    PACKAGES, UserHandle.getUserId(uid));
            return matches(config, context.getPackageManager().getPackagesForUid(uid));
        } finally {
            Binder.restoreCallingIdentity(token);
        }
    }

    public static boolean isDebugSetting(String name) {
        return "adb_enabled".equals(name) || "adb_wifi_enabled".equals(name)
                || "development_settings_enabled".equals(name);
    }

    /** Preserve the device's real non-ADB USB functions, including charging-only. */
    public static String withoutAdb(String functions) {
        List<String> remaining = new ArrayList<>();
        for (String function : functions.split(",")) {
            if (!function.isEmpty() && !"adb".equals(function)) remaining.add(function);
        }
        return remaining.isEmpty() ? "none" : TextUtils.join(",", remaining);
    }

    /**
     * Filter a copy on entry to this selected app, including sticky-cache returns.
     * No provider IPC here: receiver dispatch must not call back into system services.
     * Raw Binder clients and native socket observations are not covered.
     */
    public static Intent filterUsbBroadcast(Intent intent) {
        if (!sHideInProcess || intent == null
                || !UsbManager.ACTION_USB_STATE.equals(intent.getAction())) return intent;
        Intent filtered = new Intent(intent);
        filtered.putExtra(UsbManager.USB_FUNCTION_ADB, false);
        filtered.putExtra(UsbManager.USB_FUNCTION_MTP, true);
        return filtered;
    }

    /** Same private property-area virtualization engine used by built-in PIF. */
    public static void initializeProcess(Context context) {
        if (Process.isIsolated()
                || UserHandle.getAppId(Process.myUid()) < Process.FIRST_APPLICATION_UID) return;
        try {
            // The provider authenticates Binder UID. Never expose the configured package list.
            Bundle policy = context.getContentResolver().call(
                    Uri.parse("content://settings"), CALL_POLICY, null, null);
            if (policy == null || !policy.getBoolean("hide", false)) return;
            sHideInProcess = true;
            String[] keys = {
                "init.svc.adbd", "init.svc_debug_pid.adbd",
                "sys.usb.config", "sys.usb.state", "persist.sys.usb.config",
                "service.adb.root", "service.adb.tcp.port", "persist.adb.tcp.port",
                "service.adb.tls.port", "service.adb.listen_addrs",
                "persist.adb.tls_server.enable"
            };
            String[] values = {
                "stopped", "",
                "mtp",
                "mtp",
                "mtp",
                "", "", "", "", "", "0"
            };
            if (!android.security.pif.PlayIntegritySpoofService.getInstance()
                    .spoofAdbProperties(keys, values)) {
                Log.w(TAG, "Could not virtualize ADB properties");
            }
        } catch (RuntimeException | LinkageError e) {
            // Never fail app startup merely because privacy initialization was unavailable.
            Log.w(TAG, "ADB property privacy unavailable", e);
        }
    }

}
