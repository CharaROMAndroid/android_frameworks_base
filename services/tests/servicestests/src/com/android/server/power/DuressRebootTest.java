/*
 * Copyright (C) 2008 The Android Open Source Project
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


package com.android.server.power;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class DuressRebootTest {
    @Test
    public void rebootReasons_areExact() {
        assertTrue(DuressReboot.isDuressReboot("recovery-duress"));
        assertTrue(DuressReboot.isDuressReboot("duress"));
        for (String reason : new String[] {null, "", "recovery", "recovery-update",
                "recovery-duress,quiescent", "duress-other", "userrequested"}) {
            assertFalse(DuressReboot.isDuressReboot(reason));
        }
    }

    @Test
    public void command_acceptsGeneratedWipe() {
        assertTrue(DuressReboot.isDuressWipeCommand("--wipe_data\n--reason=duress"));
        assertTrue(DuressReboot.isDuressWipeCommand(
                "--wipe_data\n--reason=duress,2026-10-24T15:00:00-0400\n--locale=en-US\n"));
        assertTrue(DuressReboot.isDuressWipeCommand(
                "--shutdown_after\n--wipe_data\n--reason=duress\n--keep_memtag_mode"));
    }

    @Test
    public void command_rejectsOtherOperationsAndLookalikes() {
        for (String command : new String[] {null, "", "--wipe_data", "--reason=duress",
                "--wipe_data\n--reason=duress-other", "--wipe_data\n--reason=userrequested",
                "--wipe_data\n--reason=duress\n--show_text",
                "--wipe_data\n--reason=duress\n--fastboot",
                "--wipe_data\n--reason=duress\n--update_package=/tmp/update.zip",
                "--wipe_data\n--reason=duress\n--wipe_data",
                "--wipe_data\n--reason=duress\n--reason=userrequested",
                "--wipe_data\n--reason=duress\n--reason=duress",
                "--wipe_data\n--reason=duress\n--prompt_and_wipe_data"}) {
            assertFalse(command, DuressReboot.isDuressWipeCommand(command));
        }
    }

    @Test
    public void caller_requiresSystemUidAndSameProcess() {
        assertTrue(DuressReboot.isTrustedCaller(1000, 123, 1000, 123));
        assertFalse(DuressReboot.isTrustedCaller(1000, 124, 1000, 123));
        assertFalse(DuressReboot.isTrustedCaller(10001, 123, 1000, 123));
        assertFalse(DuressReboot.isTrustedCaller(0, 123, 1000, 123));
    }
}
