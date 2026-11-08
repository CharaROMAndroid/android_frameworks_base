/*
 * Copyright (C) 2026 CharaROM
 * Inspired by BaikalOS app profiles, Sergei Vasilev and BaikalOS contributors.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 */
package com.android.server.pm;

import android.annotation.Nullable;
import android.app.ApplicationPackageManager;
import android.app.AppOpsManager;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.Context;
import android.content.ContentResolver;
import android.content.pm.PackageManager;
import android.database.ContentObserver;
import android.net.Uri;
import android.os.Handler;
import android.os.Process;
import android.os.UserHandle;
import android.provider.Settings;
import android.util.ArraySet;
import android.util.Pair;
import android.util.Slog;

import com.android.server.LocalServices;
import com.android.server.pm.pkg.PackageStateInternal;
import com.android.server.pm.pkg.SharedUserApi;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Caller-side package visibility restriction, evaluated before AppsFilter's normal cache.
 * No provider/Binder calls are made on the package query path. Policy is per caller user,
 * keyed by installed package identity, never by a persisted/reusable UID.
 */
final class CharaAppListPolicy {
    static final String SETTING = "chararom_app_list_hiding";
    private static final int MAX_SETTING_LENGTH = 256 * 1024;
    private static final int MAX_PACKAGES = 4096;
    private static final int MAX_JSON_DEPTH = 16;
    private static final String TAG = "CharaAppListPolicy";

    private static volatile Map<Integer, Set<String>> sRestricted = Collections.emptyMap();
    private static boolean sStarted;

    private CharaAppListPolicy() {}

    static synchronized void start(Context context, Handler handler) {
        if (sStarted) return;
        sStarted = true;
        final ContentResolver resolver = context.getContentResolver();
        resolver.registerContentObserver(Settings.Secure.getUriFor(SETTING), false,
                new ContentObserver(handler) {
                    @Override
                    public void onChange(boolean selfChange, Uri uri, int userId) {
                        reload(resolver);
                    }
                }, UserHandle.USER_ALL);
        final IntentFilter lifecycle = new IntentFilter();
        lifecycle.addAction(Intent.ACTION_USER_ADDED);
        lifecycle.addAction(Intent.ACTION_USER_REMOVED);
        lifecycle.addAction(Intent.ACTION_USER_STARTED);
        lifecycle.addAction(Intent.ACTION_USER_UNLOCKED);
        context.registerReceiverAsUser(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                reload(resolver);
            }
        }, UserHandle.ALL, lifecycle, null, handler);
        // Register first so a concurrent settings write cannot escape observation.
        // Load all extant users before applications are started.
        reload(resolver);
    }

    private static synchronized void reload(ContentResolver resolver) {
        final UserManagerInternal users = LocalServices.getService(UserManagerInternal.class);
        if (users == null) return;
        final Map<Integer, Set<String>> next = new HashMap<>();
        for (int userId : users.getUserIds()) {
            try {
                next.put(userId, parse(Settings.Secure.getStringForUser(
                        resolver, SETTING, userId)));
            } catch (JSONException | RuntimeException e) {
                // Keep this user's last known-good policy on a corrupt/oversized write.
                Slog.w(TAG, "Ignoring invalid app-list policy for user " + userId);
                next.put(userId, sRestricted.getOrDefault(userId, Collections.emptySet()));
            }
        }
        sRestricted = Collections.unmodifiableMap(next);
        // Package info, UID membership and intent results may be cached in app processes.
        PackageManager.invalidatePackageInfoCache();
        ApplicationPackageManager.invalidateGetPackagesForUidCache();
        ApplicationPackageManager.invalidateQueryIntentActivitiesCache();
        AppOpsManager.invalidateCheckPackageCache();
    }

    static Set<String> parse(@Nullable String raw) throws JSONException {
        if (raw == null || raw.isEmpty()) return Collections.emptySet();
        if (raw.length() > MAX_SETTING_LENGTH) throw new JSONException("Policy too large");
        // JSONObject recursively parses ignored values too. Bound nesting before calling it,
        // so a corrupt privileged settings write cannot overflow system_server's stack.
        int depth = 0;
        boolean inString = false;
        boolean escaped = false;
        char quote = 0;
        for (int i = 0; i < raw.length(); i++) {
            final char ch = raw.charAt(i);
            if (inString) {
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == quote) inString = false;
            } else if (ch == '"' || ch == '\'') {
                // Android's JSON parser also accepts single-quoted strings.
                inString = true;
                quote = ch;
            } else if (ch == '/' || ch == '#') {
                // Disallow JSONTokener's nonstandard comments; quotes in comments must
                // not hide recursive values from the depth guard.
                throw new JSONException("Comments are not supported");
            } else if (ch == '{' || ch == '[') {
                if (++depth > MAX_JSON_DEPTH) throw new JSONException("Policy too deep");
            } else if (ch == '}' || ch == ']') {
                --depth;
                if (depth < 0) throw new JSONException("Unbalanced policy");
            }
        }
        if (inString || depth != 0) throw new JSONException("Unbalanced policy");
        final JSONObject json = new JSONObject(raw);
        if (json.length() > MAX_PACKAGES) throw new JSONException("Too many packages");
        final Set<String> packages = new ArraySet<>();
        final Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            final String name = keys.next();
            if (Boolean.TRUE.equals(json.opt(name)) && !name.isEmpty()) packages.add(name);
        }
        return Collections.unmodifiableSet(packages);
    }

    static boolean shouldFilter(Computer snapshot, int callingUid,
            @Nullable PackageStateInternal target) {
        if (target == null || target.isSystem()) return false;
        if (Process.isSdkSandboxUid(callingUid)) {
            callingUid = Process.getAppUidForSdkSandboxUid(callingUid);
        }
        if (Process.isPrivateComputeCoreUid(callingUid)) {
            callingUid = Process.getAppUidForPrivateComputeCoreUid(callingUid);
        }
        // ComputerEngine resolves isolated owners before reaching us. Direct paths retain
        // native isolated-process behavior instead of imposing an off-by-default policy.
        if (Process.isIsolated(callingUid)) return false;
        final int appId = UserHandle.getAppId(callingUid);
        if (appId < Process.FIRST_APPLICATION_UID || appId == target.getAppId()) return false;
        final int callerUser = UserHandle.getUserId(callingUid);
        final Set<String> restricted = sRestricted.get(callerUser);
        if (restricted == null || restricted.isEmpty()) return false;
        final Pair<PackageStateInternal, SharedUserApi> caller =
                snapshot.getPackageOrSharedUser(appId);
        if (caller == null) return false;
        if (caller.second != null) {
            for (PackageStateInternal member : caller.second.getPackageStates()) {
                if (member.getUserStateOrDefault(callerUser).isInstalled()
                        && restricted.contains(member.getPackageName())) return true;
            }
        }
        return caller.first != null
                && caller.first.getUserStateOrDefault(callerUser).isInstalled()
                && restricted.contains(caller.first.getPackageName());
    }
}
