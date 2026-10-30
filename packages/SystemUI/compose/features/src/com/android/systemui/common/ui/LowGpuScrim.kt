/*
 * Copyright (C) 2026 The CharaROM Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.systemui.common.ui

import android.os.SystemProperties

/**
 * Opt-in scrim rendering for low-end GPUs, based on Project-Wisdom.
 *
 * Read once per SystemUI process so scene compositing and scrim drawing always agree. This readonly
 * property must be configured at boot; absent or false preserves the standard rendering path.
 * Enable only on devices validated for shade, QS and lockscreen transition visuals.
 */
internal object LowGpuScrim {
    val enabled: Boolean = SystemProperties.getBoolean("ro.chara.lowgpu_scrim", false)
}
