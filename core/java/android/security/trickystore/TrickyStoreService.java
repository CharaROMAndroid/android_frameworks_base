/*
 * Copyright (C) 2025-2026 AxionOS
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

package android.security.trickystore;

import android.app.ActivityManager;
import android.app.IActivityManager;
import android.os.RemoteException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.JsonReader;
import android.util.Log;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @hide
 */
public class TrickyStoreService {
    private static final String TAG = "TrickyStoreService";

    private static TrickyStoreService sInstance;

    // Revocation check runs from system_server over the network (background thread,
    // 24h cooldown) and is logging-only — it never changes keybox state.
    private static final boolean ENABLE_REVOCATION_CHECK = false;

    private final Set<String> mHackPackages = ConcurrentHashMap.newKeySet();
    private final Set<String> mGeneratePackages = ConcurrentHashMap.newKeySet();
    private final Set<String> mSkipPackages = ConcurrentHashMap.newKeySet();
    private final Map<String, Mode> mPackageModes = new ConcurrentHashMap<>();

    private volatile Boolean mTeeBroken = null;
    // A "healthy" result is cached for the process lifetime; a "broken" one is
    // re-checked after this long, so one transient keystore failure (early boot,
    // exhausted RKP key pool) doesn't force GENERATE mode until the next reboot.
    private static final long TEE_RECHECK_COOLDOWN_MS = 5L * 60 * 1000L;
    private volatile long mTeeCheckedAtMs = 0L;
    private volatile long mLastRevocationCheckMs = 0L;
    private volatile long mLastTargetsRefreshMs = 0L;
    private static final long TARGETS_REFRESH_COOLDOWN_MS = 5_000L;
    private static final long REVOCATION_CHECK_COOLDOWN_MS = 24 * 60 * 60 * 1000L;
    private static final long CACHE_TRUST_WINDOW_MS = 7L * 24 * 60 * 60 * 1000L;
    private static final java.io.File REVOCATION_CACHE_FILE =
        new java.io.File("/data/system/trickystore/revocation_cache.json");
    private volatile CustomPatchLevel mCustomPatchLevel = null;
    private final Map<String, CustomPatchLevel> mPerPackagePatchLevels = new ConcurrentHashMap<>();
    // Attesting through a hooked process breaks STRONG — always skipped
    // regardless of what mode the target list has for them, and never
    // auto-targeted by AxSpoofManager. Shared so the two can't drift apart.
    public static final java.util.Set<String> XPOSED_PACKAGES = java.util.Set.of(
            "org.lsposed.manager",
            "io.github.lsposed.manager",
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "com.solohsu.android.edxp.manager",
            "io.va.exposed",
            "com.topjohnwu.lsplant.manager",
            "me.weishu.exposed"
    );
    // Default TrickyStore targets, in the same syntax as SPOOF_TRICKYSTORE_TARGET:
    // "pkg" is AUTO, "pkg?" leaf hack, "pkg!" cert generation, "pkg-" skip.
    // AxSpoofManager writes this into a target setting that was never set, so a
    // fresh install attests GMS and friends by default.
    public static final String DEFAULT_TARGET_LIST = String.join("\n",
            "android",
            // GMS and friends, AUTO mode
            "com.android.vending",
            "com.google.android.gsf",
            "com.google.android.gms",
            "com.google.android.contactkeys",
            "com.google.android.ims",
            "com.google.android.safetycore",
            "com.google.android.apps.walletnfcrel",
            "com.google.android.apps.nbu.paisa.user",
            // Cert generation
            "com.revolut.revolut!",
            // Key attestation checkers, leaf hack
            "io.github.qwq233.keyattestation?",
            "io.github.vvb2060.keyattestation?",
            "io.github.vvb2060.mahoshojo?",
            "icu.nullptr.nativetest?",
            "com.reveny.nativecheck?",
            "com.zhenxi.hunter?",
            "com.android.nativetest?",
            "io.liankong.riskdetector?",
            "luna.safe.luna?",
            "com.eltavine.duckdetector?",
            "com.rem01gaming.disclosure?",
            "wu.keyChain.test?",
            "com.kikyps.crackme?",
            "com.chunqiunativecheck?"
    );
    private volatile String mLastKeyboxFingerprint = null;

    private KeyBoxManager mKeyBoxManager;
    private static final ThreadLocal<TrickyStoreService> SERVER_CONFIG = new ThreadLocal<>();

    /** System-server request-scoped config. Never used for application key imports. */
    public static void setServerConfig(String targets, String patch, KeyBoxManager manager) {
        if (android.os.Process.myUid() != android.os.Process.SYSTEM_UID) {
            throw new SecurityException("system_server only");
        }
        if (manager == null) { SERVER_CONFIG.remove(); return; }
        TrickyStoreService config = new TrickyStoreService();
        config.mKeyBoxManager = manager;
        if (targets != null) {
            try {
                if (targets.trim().startsWith("[")) config.parseTargetsJson(targets);
                else config.parseTargetsText(targets);
            } catch (Exception e) { throw new IllegalArgumentException("Invalid targets"); }
        }
        if (patch != null) {
            try {
                if (patch.trim().startsWith("{")) config.parsePatchJson(patch);
                else config.parsePatchText(patch);
            } catch (Exception e) { throw new IllegalArgumentException("Invalid patch config"); }
        }
        SERVER_CONFIG.set(config);
    }

    public Mode configuredMode(String pkg) { return mPackageModes.get(pkg); }


    /** @hide */
    public enum Mode {
        AUTO, LEAF_HACK, GENERATE, SKIP
    }

    /** @hide */
    public static class CustomPatchLevel {
        public final String system;
        public final String vendor;
        public final String boot;
        public final String all;

        public CustomPatchLevel(String system, String vendor, String boot, String all) {
            this.system = system;
            this.vendor = vendor;
            this.boot = boot;
            this.all = all;
        }
    }

    private TrickyStoreService() {
        // Issuer keys are held exclusively by the system-side signer.
    }

    public static synchronized TrickyStoreService getInstance() {
        if (SERVER_CONFIG.get() != null) return SERVER_CONFIG.get();
        if (sInstance == null) {
            sInstance = new TrickyStoreService();
            sInstance.initialize();
        }
        return sInstance;
    }

    public void initialize() {
        refreshTargets();
        refreshKeyBox();
        refreshPatchLevel();
        Log.i(TAG, "TrickyStoreService initialized");
    }

    private String fetchFromAms(Fetcher fetcher) {
        IActivityManager am = ActivityManager.getService();
        if (am == null) {
            Log.w(TAG, "ActivityManager not ready, skipping trickystore fetch");
            return null;
        }
        try {
            return fetcher.fetch(am);
        } catch (Throwable e) {
            Log.e(TAG, "Failed to fetch trickystore config from system_server", e);
            return null;
        }
    }

    private interface Fetcher {
        String fetch(IActivityManager am) throws RemoteException;
    }

    public void refreshTargets() {
        String content = fetchFromAms(am -> am.getSpoofTrickyStoreTarget());
        mHackPackages.clear();
        mGeneratePackages.clear();
        mSkipPackages.clear();
        mPackageModes.clear();

        if (content == null || content.isEmpty()) {
            return;
        }

        String trimmed = content.trim();
        try {
            if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
                parseTargetsJson(trimmed);
            } else {
                parseTargetsText(trimmed);
            }
            Log.i(TAG, "Updated target packages: hack=" + mHackPackages +
                  ", generate=" + mGeneratePackages + ", skip=" + mSkipPackages +
                  ", modes=" + mPackageModes);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse target packages", e);
        }
    }

    private void parseTargetsText(String content) {
        for (String raw : content.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            if (line.endsWith("!")) {
                String pkg = line.substring(0, line.length() - 1).trim();
                mGeneratePackages.add(pkg);
                mPackageModes.put(pkg, Mode.GENERATE);
            } else if (line.endsWith("?")) {
                String pkg = line.substring(0, line.length() - 1).trim();
                mHackPackages.add(pkg);
                mPackageModes.put(pkg, Mode.LEAF_HACK);
            } else if (line.endsWith("-")) {
                String pkg = line.substring(0, line.length() - 1).trim();
                mSkipPackages.add(pkg);
                mPackageModes.put(pkg, Mode.SKIP);
            } else {
                mPackageModes.put(line, Mode.AUTO);
            }
        }
    }

    private void parseTargetsJson(String content) throws IOException {
        try (JsonReader reader = new JsonReader(new StringReader(content))) {
            reader.beginArray();
            while (reader.hasNext()) {
                reader.beginObject();
                String pkg = null;
                String modeStr = "AUTO";
                while (reader.hasNext()) {
                    String key = reader.nextName();
                    if ("package".equals(key)) {
                        pkg = reader.nextString();
                    } else if ("mode".equals(key)) {
                        modeStr = reader.nextString();
                    } else {
                        reader.skipValue();
                    }
                }
                reader.endObject();
                if (pkg == null) continue;
                Mode mode;
                try {
                    mode = Mode.valueOf(modeStr.toUpperCase());
                } catch (IllegalArgumentException e) {
                    mode = Mode.AUTO;
                }
                mPackageModes.put(pkg, mode);
                if (mode == Mode.LEAF_HACK) mHackPackages.add(pkg);
                if (mode == Mode.GENERATE) mGeneratePackages.add(pkg);
                if (mode == Mode.SKIP) mSkipPackages.add(pkg);
            }
            reader.endArray();
        }
    }

    public void refreshKeyBox() { /* Compatibility no-op; no issuer key IPC. */ }

    public void refreshPatchLevel() {
        if (SERVER_CONFIG.get() == this) return;
        mCustomPatchLevel = null;
        String content = fetchFromAms(am -> am.getSpoofTrickyStorePatch());
        mPerPackagePatchLevels.clear();
        if (content == null || content.isEmpty()) {
            mCustomPatchLevel = null;
            return;
        }

        try {
            String trimmed = content.trim();
            if (trimmed.startsWith("{")) {
                parsePatchJson(trimmed);
            } else {
                parsePatchText(trimmed);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse patch level", e);
        }
    }

    private void parsePatchText(String content) {
        String currentPackage = null;
        String system = null, vendor = null, boot = null, all = null;

        for (String raw : content.split("\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;

            if (line.startsWith("[") && line.endsWith("]")) {
                flushPatchSection(currentPackage, system, vendor, boot, all);
                currentPackage = line.substring(1, line.length() - 1).trim();
                system = vendor = boot = all = null;
                continue;
            }

            int idx = line.indexOf('=');
            if (idx > 0) {
                String key = line.substring(0, idx).trim().toLowerCase();
                String value = line.substring(idx + 1).trim();
                switch (key) {
                    case "system": system = value; break;
                    case "vendor": vendor = value; break;
                    case "boot":   boot   = value; break;
                    case "all":    all    = value; break;
                }
            } else {
                all = line;
            }
        }
        flushPatchSection(currentPackage, system, vendor, boot, all);
    }

    private static String resolvePatchTemplate(String value) {
        if (value == null) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("^YYYY-MM-(\\d{2})$").matcher(value.trim());
        if (!m.matches()) return value;
        String day = m.group(1);
        java.util.Calendar cal = java.util.Calendar.getInstance(
            java.util.TimeZone.getTimeZone("UTC"));
        return String.format(java.util.Locale.US, "%04d-%02d-%s",
            cal.get(java.util.Calendar.YEAR),
            cal.get(java.util.Calendar.MONTH) + 1,
            day);
    }

    private void flushPatchSection(String pkg, String system, String vendor, String boot, String all) {
        if (system == null && vendor == null && boot == null && all == null) return;
        String resolvedAll    = resolvePatchTemplate(all);
        String resolvedSystem = resolvePatchTemplate(system);
        String resolvedVendor = resolvePatchTemplate(vendor);
        String resolvedBoot   = resolvePatchTemplate(boot);
        CustomPatchLevel level = new CustomPatchLevel(
            resolvedSystem != null ? resolvedSystem : resolvedAll,
            resolvedVendor != null ? resolvedVendor : resolvedAll,
            resolvedBoot   != null ? resolvedBoot   : resolvedAll,
            resolvedAll
        );
        if (pkg == null) {
            mCustomPatchLevel = level;
        } else {
            mPerPackagePatchLevels.put(pkg, level);
        }
    }

    private void parsePatchJson(String content) throws IOException {
        String system = null, vendor = null, boot = null, all = null;
        try (JsonReader reader = new JsonReader(new StringReader(content))) {
            reader.beginObject();
            while (reader.hasNext()) {
                String key = reader.nextName();
                switch (key) {
                    case "system": system = reader.nextString(); break;
                    case "vendor": vendor = reader.nextString(); break;
                    case "boot":   boot   = reader.nextString(); break;
                    case "all":    all    = reader.nextString(); break;
                    case "packages":
                        reader.beginObject();
                        while (reader.hasNext()) {
                            String pkg = reader.nextName();
                            String ps = null, pv = null, pb = null, pa = null;
                            reader.beginObject();
                            while (reader.hasNext()) {
                                String pk = reader.nextName();
                                switch (pk) {
                                    case "system": ps = reader.nextString(); break;
                                    case "vendor": pv = reader.nextString(); break;
                                    case "boot":   pb = reader.nextString(); break;
                                    case "all":    pa = reader.nextString(); break;
                                    default: reader.skipValue(); break;
                                }
                            }
                            reader.endObject();
                            flushPatchSection(pkg, ps, pv, pb, pa);
                        }
                        reader.endObject();
                        break;
                    default: reader.skipValue(); break;
                }
            }
            reader.endObject();
        }
        flushPatchSection(null, system, vendor, boot, all);
    }

    private boolean isTeeStatusFresh() {
        Boolean cached = mTeeBroken;
        return cached != null && (!cached
                || System.currentTimeMillis() - mTeeCheckedAtMs < TEE_RECHECK_COOLDOWN_MS);
    }

    private void ensureTeeStatus() {
        if (isTeeStatusFresh()) return;
        synchronized (this) {
            if (isTeeStatusFresh()) return;
            boolean broken = checkTeeBroken();
            mTeeBroken = broken;
            mTeeCheckedAtMs = System.currentTimeMillis();
            AttestationUtils.setTeeBroken(broken);
        }
    }

    private boolean checkTeeBroken() {
        // Retain the recognized internal prefix while avoiding an app-owned alias.
        String alias = "TrickyStoreTeeCheck-" + java.util.UUID.randomUUID();
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(new byte[16]);
            kpg.initialize(builder.build());
            kpg.generateKeyPair();
            return false;
        } catch (Exception e) {
            return true;
        } finally {
            if (ks != null) {
                try { ks.deleteEntry(alias); } catch (Exception ignored) { }
            }
        }
    }

    public boolean needHack(int callingUid, String[] packages) {
        if (packages == null) return false;
        maybeRefreshTargets();
        for (String pkg : packages) {
            if (XPOSED_PACKAGES.contains(pkg)) continue;
            Mode mode = mPackageModes.get(pkg);
            if (mode == Mode.SKIP) continue;
            if (mode == Mode.LEAF_HACK) return true;
            // Only AUTO needs to know the TEE state. Probing it costs a real
            // attested key generation, so don't do it for untargeted apps.
            if (mode == Mode.AUTO && !isTeeBroken()) return true;
        }
        return false;
    }

    public boolean needGenerate(int callingUid, String[] packages) {
        if (packages == null) return false;
        maybeRefreshTargets();
        for (String pkg : packages) {
            if (XPOSED_PACKAGES.contains(pkg)) continue;
            Mode mode = mPackageModes.get(pkg);
            if (mode == Mode.SKIP) continue;
            if (mode == Mode.GENERATE) return true;
            if (mode == Mode.AUTO && isTeeBroken()) return true;
        }
        return false;
    }

    private void maybeRefreshTargets() {
        long now = System.currentTimeMillis();
        if (now - mLastTargetsRefreshMs >= TARGETS_REFRESH_COOLDOWN_MS) {
            mLastTargetsRefreshMs = now;
            refreshTargets();
        }
    }

    public KeyBoxManager getKeyBoxManager() {
        return SERVER_CONFIG.get() == this ? mKeyBoxManager : null;
    }

    public CustomPatchLevel getCustomPatchLevel() {
        refreshPatchLevel();
        return mCustomPatchLevel;
    }

    public CustomPatchLevel getCustomPatchLevelForPackage(String[] packages) {
        refreshPatchLevel();
        if (packages != null) {
            for (String pkg : packages) {
                CustomPatchLevel level = mPerPackagePatchLevels.get(pkg);
                if (level != null) {
                    CustomPatchLevel global = mCustomPatchLevel;
                    return new CustomPatchLevel(
                        level.system != null ? level.system : global == null ? null : global.system,
                        level.vendor != null ? level.vendor : global == null ? null : global.vendor,
                        level.boot != null ? level.boot : global == null ? null : global.boot,
                        level.all != null ? level.all : global == null ? null : global.all);
                }
            }
        }
        return mCustomPatchLevel;
    }

    /**
     * Returns true if the given patch date string is more than 12 months old.
     * Accepts YYYY-MM-DD only; unparsable or null input is treated as not stale
     * (we don't want to warn on a value we can't understand).
     */
    private static final long PATCH_STALE_THRESHOLD_MS = 365L * 24 * 60 * 60 * 1000L;

    public static boolean isPatchLevelStale(String patchDate) {
        if (patchDate == null || patchDate.isEmpty()) return false;
        try {
            java.text.SimpleDateFormat sdf =
                new java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.US);
            sdf.setLenient(false);
            long patchMs = sdf.parse(patchDate.trim()).getTime();
            return System.currentTimeMillis() - patchMs > PATCH_STALE_THRESHOLD_MS;
        } catch (Exception e) {
            return false;
        }
    }

    public boolean hasKeyboxes() {
        try { return ActivityManager.getService().hasTrickyStoreKeyboxes(); }
        catch (Exception e) { return false; }
    }

    /**
     * Returns whether the TEE is broken, forcing the check if it hasn't run yet.
     * Safe to call from any thread; the underlying check is synchronized.
     */
    public boolean isTeeBroken() {
        ensureTeeStatus();
        return Boolean.TRUE.equals(mTeeBroken);
    }

    public List<java.security.cert.Certificate> requestCertificateChain(
            java.security.PublicKey key, CertificateGenerator.KeyGenParameters p, int level) {
        try {
            android.os.Bundle b = new android.os.Bundle();
            b.putInt("level", level);
            if (p.certificateSubject != null) b.putByteArray("subject", p.certificateSubject.getEncoded());
            if (p.certificateSerial != null) b.putByteArray("serial", p.certificateSerial.toByteArray());
            if (p.certificateNotBefore != null) b.putLong("notBefore", p.certificateNotBefore.getTime());
            if (p.certificateNotAfter != null) b.putLong("notAfter", p.certificateNotAfter.getTime());
            b.putByteArray("challenge", p.attestationChallenge);
            b.putIntegerArrayList("purpose", new ArrayList<>(p.purpose));
            b.putIntegerArrayList("digest", new ArrayList<>(p.digest));
            b.putIntegerArrayList("padding", new ArrayList<>(p.padding));
            b.putIntegerArrayList("mgfDigest", new ArrayList<>(p.rsaOaepMgfDigest));
            byte[] encoded = ActivityManager.getService().signTrickyStoreCertificate(
                    key.getEncoded(), key.getAlgorithm(), b);
            if (encoded == null) return null;
            return new ArrayList<>(java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificates(new java.io.ByteArrayInputStream(encoded)));
        } catch (Exception e) { return null; }
    }

    public java.security.cert.Certificate[] requestRewrittenChain(
            java.security.cert.Certificate[] chain) {
        if (chain == null || chain.length == 0 || chain.length > 8) return chain;
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            for (var cert : chain) {
                byte[] der = cert.getEncoded();
                if (der.length > 16384 || out.size() + der.length > 65536) return chain;
                out.write(der);
            }
            byte[] encoded = ActivityManager.getService().rewriteTrickyStoreCertificateChain(out.toByteArray());
            if (encoded == null) return chain;
            var result = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificates(new java.io.ByteArrayInputStream(encoded));
            return result.toArray(new java.security.cert.Certificate[0]);
        } catch (Exception e) { return chain; }
    }
}
