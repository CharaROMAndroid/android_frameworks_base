/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.graphics.fonts;
import android.os.SharedMemory;
/** @hide */
oneway interface IFontSanitizerCallback {
    void onResult(in SharedMemory output);
}
