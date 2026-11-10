/*
 * Copyright (C) 2026 CharaROM
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.usb;

import android.hardware.usb.UsbManager;

/** Pure selection rule; USB handler owns and revalidates the permission/lock snapshot. */
final class UsbAdbSafetyPolicy {
    private UsbAdbSafetyPolicy() {}

    static long constrain(long requested, boolean transferAllowed) {
        return transferAllowed && requested == UsbManager.FUNCTION_MTP
                ? UsbManager.FUNCTION_MTP : UsbManager.FUNCTION_NONE;
    }
}
