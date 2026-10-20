package com.android.fontsanitizer;

import android.app.Service;
import android.content.Intent;
import android.graphics.fonts.IFontSanitizer;
import android.graphics.fonts.IFontSanitizerCallback;
import android.os.Binder;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.RemoteException;
import android.os.SharedMemory;
import android.system.OsConstants;

import java.nio.ByteBuffer;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/** No font metadata is parsed in a privileged process. */
public final class FontSanitizerService extends Service {
    private static final int MAX_BYTES = 32 * 1024 * 1024;
    static {
        System.loadLibrary("fontsanitizer_jni");
    }

    private final AtomicBoolean mBusy = new AtomicBoolean();
    private final ExecutorService mWorker = Executors.newSingleThreadExecutor();
    private final ScheduledExecutorService mWatchdog =
            Executors.newSingleThreadScheduledExecutor();

    private final IFontSanitizer.Stub mBinder = new IFontSanitizer.Stub() {
        @Override
        public void sanitize(ParcelFileDescriptor input, IFontSanitizerCallback callback) {
            // Also enforce at the Binder entry point in case a handle is passed around.
            if (Binder.getCallingUid() != Process.SYSTEM_UID || input == null
                    || callback == null) {
                closeInput(input);
                reject(callback);
                return;
            }
            if (!mBusy.compareAndSet(false, true)) {
                closeInput(input);
                reject(callback);
                return;
            }
            try {
                // Separate from worker and main looper so stuck native work cannot
                // prevent timeout termination.
                ScheduledFuture<?> timeout = mWatchdog.schedule(
                        () -> Process.killProcess(Process.myPid()), 10, TimeUnit.SECONDS);
                try {
                    mWorker.execute(() -> runJob(input, callback, timeout));
                } catch (RuntimeException e) {
                    timeout.cancel(false);
                    mBusy.set(false);
                    closeInput(input);
                    reject(callback);
                }
            } catch (RuntimeException e) {
                mBusy.set(false);
                closeInput(input);
                reject(callback);
            }
        }
    };

    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }

    private void runJob(ParcelFileDescriptor input, IFontSanitizerCallback callback,
            ScheduledFuture<?> timeout) {
        SharedMemory memory = null;
        try (ParcelFileDescriptor owned = input) {
            byte[] rewritten = nativeSanitize(owned.getFd());
            if (rewritten == null || rewritten.length == 0 || rewritten.length > MAX_BYTES) {
                reject(callback);
                return;
            }
            memory = SharedMemory.create("sanitized-font", rewritten.length);
            ByteBuffer mapped = memory.mapReadWrite();
            try {
                mapped.put(rewritten);
            } finally {
                SharedMemory.unmap(mapped);
            }
            if (!memory.setProtect(OsConstants.PROT_READ)) {
                reject(callback);
                return;
            }
            callback.onResult(memory);
        } catch (Exception | OutOfMemoryError e) {
            reject(callback);
        } finally {
            if (memory != null) memory.close();
            timeout.cancel(false);
            mBusy.set(false);
            // Never kill immediately after an asynchronous Binder callback.
            stopSelf();
        }
    }

    private static void reject(IFontSanitizerCallback callback) {
        if (callback == null) return;
        try {
            callback.onResult(null);
        } catch (RemoteException ignored) {
            // Caller died; there is nothing to deliver.
        }
    }

    private static void closeInput(ParcelFileDescriptor input) {
        if (input == null) return;
        try {
            input.close();
        } catch (java.io.IOException ignored) {
        }
    }

    @Override
    public void onDestroy() {
        // Keep an active job's timeout armed until its own finally block runs.
        mWorker.shutdown();
        mWatchdog.shutdown();
        super.onDestroy();
    }

    private static native byte[] nativeSanitize(int fd);
}
