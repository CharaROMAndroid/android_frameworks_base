/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package com.android.server.graphics.fonts;

import android.system.Os;
import android.system.ErrnoException;
import android.util.AtomicFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Authenticates the fs-verity digest of locally sanitized output across reboots.
 *
 * Only system_server calls issue(), after copying successful isolated-worker output and enabling
 * fs-verity. Callers cannot turn raw uploads into trusted files by supplying their own receipt.
 * This is provenance/integrity, not proof of absence of renderer bugs. Bump POLICY when changing
 * OTS or sanitizer policy so old output must be sanitized again, never parsed as current output.
 */
final class FontSanitizationReceipt {
    // Independent of provider PKCS#7 signatures, which start with an ASN.1 sequence.
    private static final byte[] MAGIC = {'O', 'T', 'S', 'F', 'O', 'N', 'T', 1};
    private static final byte[] POLICY = "OTS-output-policy-v2-unhinted".getBytes(StandardCharsets.US_ASCII);
    private static final int KEY_BYTES = 32;
    private static final int DIGEST_BYTES = 32;
    private final AtomicFile mKeyFile;
    private byte[] mKey;

    FontSanitizationReceipt(File keyFile) {
        mKeyFile = new AtomicFile(keyFile);
    }

    static boolean isReceipt(byte[] value) {
        if (value == null || value.length != MAGIC.length + DIGEST_BYTES) return false;
        for (int i = 0; i < MAGIC.length; i++) if (value[i] != MAGIC[i]) return false;
        return true;
    }

    synchronized byte[] issue(byte[] digest) throws IOException {
        if (digest == null || digest.length != DIGEST_BYTES) {
            throw new IOException("No immutable font digest");
        }
        byte[] key = readKey();
        if (key == null) {
            key = new byte[KEY_BYTES];
            new SecureRandom().nextBytes(key);
            FileOutputStream out = null;
            try {
                out = mKeyFile.startWrite();
                try {
                    Os.fchmod(out.getFD(), 0600);
                } catch (ErrnoException e) {
                    throw new IOException("Cannot protect font receipt key", e);
                }
                out.write(key);
                mKeyFile.finishWrite(out);
                out = null;
                mKey = key;
            } finally {
                if (out != null) mKeyFile.failWrite(out);
            }
        }
        byte[] mac = authenticate(key, digest);
        byte[] receipt = Arrays.copyOf(MAGIC, MAGIC.length + mac.length);
        System.arraycopy(mac, 0, receipt, MAGIC.length, mac.length);
        return receipt;
    }

    synchronized boolean verify(byte[] receipt, byte[] digest) {
        if (!isReceipt(receipt) || digest == null || digest.length != DIGEST_BYTES) return false;
        try {
            byte[] key = readKey();
            return key != null && MessageDigest.isEqual(
                    Arrays.copyOfRange(receipt, MAGIC.length, receipt.length),
                    authenticate(key, digest));
        } catch (IOException e) {
            return false;
        }
    }

    private byte[] readKey() throws IOException {
        if (mKey != null) return mKey;
        if (!mKeyFile.exists()) return null;
        try (FileInputStream in = mKeyFile.openRead()) {
            byte[] key = new byte[KEY_BYTES + 1];
            int count = 0;
            while (count < key.length) {
                int read = in.read(key, count, key.length - count);
                if (read < 0) break;
                count += read;
            }
            if (count != KEY_BYTES) throw new IOException("Invalid font receipt key");
            mKey = Arrays.copyOf(key, KEY_BYTES);
            return mKey;
        }
    }

    private static byte[] authenticate(byte[] key, byte[] digest) throws IOException {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(POLICY);
            mac.update(MAGIC);
            return mac.doFinal(digest);
        } catch (GeneralSecurityException e) {
            throw new IOException("Cannot authenticate sanitized font", e);
        }
    }
}
