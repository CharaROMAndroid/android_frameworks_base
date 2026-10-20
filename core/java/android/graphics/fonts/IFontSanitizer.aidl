/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.graphics.fonts;
import android.os.ParcelFileDescriptor;
import android.graphics.fonts.IFontSanitizerCallback;
/** @hide */
oneway interface IFontSanitizer {
    void sanitize(in ParcelFileDescriptor input, IFontSanitizerCallback callback);
}
