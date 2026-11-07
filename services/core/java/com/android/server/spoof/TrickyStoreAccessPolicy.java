/*
 * Copyright (C) 2026 The CharaROM Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.spoof;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/** Fail-closed authorization for the text target format used by Settings. */
final class TrickyStoreAccessPolicy {
    private TrickyStoreAccessPolicy() {}

    static boolean isAllowed(String targets, String[] packages, Set<String> excluded) {
        if (targets == null || packages == null || packages.length == 0) {
            return false;
        }
        final Map<String, Boolean> modes = new HashMap<>();
        for (String raw : targets.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            char suffix = line.charAt(line.length() - 1);
            boolean skip = suffix == '-';
            if (skip || suffix == '!' || suffix == '?') {
                line = line.substring(0, line.length() - 1).trim();
            }
            // JSON, unknown suffixes, duplicate/ambiguous entries and partial
            // parses must not accidentally authorize release of private keys.
            if (!line.matches("[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)*")
                    || modes.putIfAbsent(line, !skip) != null) {
                return false;
            }
        }
        boolean allowed = false;
        for (String pkg : packages) {
            // Shared UIDs are a security boundary: deny if any member is
            // explicitly excluded, even if another member is targeted.
            if (excluded.contains(pkg) || Boolean.FALSE.equals(modes.get(pkg))) {
                return false;
            }
            allowed |= Boolean.TRUE.equals(modes.get(pkg));
        }
        return allowed;
    }
}
