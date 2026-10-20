/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 */
package android.graphics.fonts;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.os.IBinder;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.os.RemoteException;
import android.os.SharedMemory;
import android.os.UserHandle;
import android.system.ErrnoException;
import android.system.OsConstants;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Client for the permissionless isolated font transcoder.
 *
 * Only rewritten, bounded output is returned. A successful sanitation reduces parser attack
 * surface; it is not proof that every downstream renderer is free of vulnerabilities.
 * Call off the main thread. Input and output are caller-owned temporary files, never URI paths.
 * @hide
 */
public final class FontSanitizer {
    public static final long MAX_FONT_BYTES = 32L * 1024 * 1024;
    private static final String PACKAGE = "com.android.fontsanitizer";
    private static final ComponentName COMPONENT = new ComponentName(
            PACKAGE, PACKAGE + ".FontSanitizerService");
    private static final long TIMEOUT_SECONDS = 15;

    private FontSanitizer() {}

    public static void sanitize(Context context, File input, File output) throws IOException {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            throw new IOException("Font sanitation must not block the main thread");
        }
        if (input.getCanonicalFile().equals(output.getCanonicalFile())) {
            throw new IOException("Input and output must be distinct");
        }
        if (!input.isFile() || input.length() <= 0 || input.length() > MAX_FONT_BYTES) {
            throw new IOException("Font input size outside allowed range");
        }
        final PackageManager pm = context.getPackageManager();
        try {
            ServiceInfo info = pm.getServiceInfo(COMPONENT,
                    PackageManager.MATCH_SYSTEM_ONLY | PackageManager.MATCH_DIRECT_BOOT_AWARE);
            if (pm.checkSignatures("android", PACKAGE) != PackageManager.SIGNATURE_MATCH
                    || (info.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) == 0
                    || (info.flags & ServiceInfo.FLAG_ISOLATED_PROCESS) == 0
                    || !info.exported
                    || !"android.permission.UPDATE_FONTS".equals(info.permission)) {
                throw new IOException("Untrusted font sanitizer service");
            }
        } catch (PackageManager.NameNotFoundException e) {
            throw new IOException("FontSanitizer must be included in the system image", e);
        }

        final CountDownLatch done = new CountDownLatch(1);
        // The callback owns each returned mapping until transferred under this lock.
        final Object lock = new Object();
        final SharedMemory[] result = new SharedMemory[1];
        final boolean[] closed = new boolean[1];
        final boolean[] delivered = new boolean[1];
        final boolean[] connected = new boolean[1];
        try (ParcelFileDescriptor fd = ParcelFileDescriptor.open(
                input, ParcelFileDescriptor.MODE_READ_ONLY)) {
            final IFontSanitizerCallback callback = new IFontSanitizerCallback.Stub() {
                @Override
                public void onResult(SharedMemory memory) {
                    synchronized (lock) {
                        if (closed[0] || delivered[0] || !connected[0]) {
                            if (memory != null) memory.close();
                            return;
                        }
                        delivered[0] = true;
                        result[0] = memory;
                    }
                    done.countDown();
                }
            };
            final ServiceConnection connection = new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder binder) {
                    synchronized (lock) {
                        if (closed[0]) return;
                        connected[0] = true;
                    }
                    try {
                        IFontSanitizer.Stub.asInterface(binder).sanitize(fd, callback);
                    } catch (RemoteException | RuntimeException e) {
                        done.countDown();
                    }
                }
                @Override
                public void onServiceDisconnected(ComponentName name) { done.countDown(); }
                @Override
                public void onBindingDied(ComponentName name) { done.countDown(); }
                @Override
                public void onNullBinding(ComponentName name) { done.countDown(); }
            };
            boolean bound = false;
            boolean success = false;
            SharedMemory memory = null;
            try {
                bound = context.bindServiceAsUser(new Intent().setComponent(COMPONENT),
                        connection, Context.BIND_AUTO_CREATE | Context.BIND_NOT_FOREGROUND,
                        UserHandle.SYSTEM);
                if (!bound || !done.await(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    throw new IOException("Font sanitizer unavailable or timed out");
                }
                synchronized (lock) {
                    closed[0] = true;
                    memory = result[0];
                    result[0] = null;
                }
                if (memory == null || memory.getSize() <= 0
                        || memory.getSize() > MAX_FONT_BYTES) {
                    throw new IOException("Font sanitizer rejected input");
                }
                if (!memory.setProtect(OsConstants.PROT_READ)) {
                    throw new IOException("Cannot seal sanitized shared memory");
                }
                final ByteBuffer buffer = memory.mapReadOnly();
                try (FileOutputStream out = new FileOutputStream(output)) {
                    // Copy into caller-owned storage. Never install an FD controlled by worker.
                    while (buffer.hasRemaining()) out.getChannel().write(buffer);
                    out.getFD().sync();
                } finally {
                    SharedMemory.unmap(buffer);
                }
                success = true;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during font sanitation", e);
            } catch (ErrnoException | RuntimeException e) {
                throw new IOException("Could not sanitize font", e);
            } finally {
                synchronized (lock) {
                    closed[0] = true;
                    if (result[0] != null) {
                        result[0].close();
                        result[0] = null;
                    }
                }
                if (memory != null) memory.close();
                if (bound) context.unbindService(connection);
                if (!success) output.delete();
            }
        }
    }
}
