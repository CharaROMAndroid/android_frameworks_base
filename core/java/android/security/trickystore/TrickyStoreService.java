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
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.Tag;
import android.os.RemoteException;
import android.security.KeyStoreSecurityLevel;
import android.security.keymaster.KeymasterDefs;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.keystore2.Authorization;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.system.keystore2.KeyMetadata;
import android.util.JsonReader;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @hide
 */
public class TrickyStoreService {
    private static final String TAG = "TrickyStoreService";

    private static TrickyStoreService sInstance;

    private final Set<String> mHackPackages = ConcurrentHashMap.newKeySet();
    private final Set<String> mGeneratePackages = ConcurrentHashMap.newKeySet();
    private final Map<String, Mode> mPackageModes = new ConcurrentHashMap<>();

    private volatile Boolean mTeeBroken = null;
    private volatile long mLastRevocationCheckMs = 0L;
    private static final long REVOCATION_CHECK_COOLDOWN_MS = 24 * 60 * 60 * 1000L;
    private volatile CustomPatchLevel mCustomPatchLevel = null;
    private volatile String mLastKeyboxFingerprint = null;

    private final KeyBoxManager mKeyBoxManager;

    /** @hide */
    public enum Mode {
        AUTO, LEAF_HACK, GENERATE
    }

    /**
     * Key identifier for software keys (uid + alias).
     * Based on TrickyStoreOSS SecurityLevelInterceptor.Key
     * @hide
     */
    public static final class SoftwareKey {
        public final int uid;
        public final String alias;
        
        public SoftwareKey(int uid, String alias) {
            this.uid = uid;
            this.alias = alias;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof SoftwareKey)) return false;
            SoftwareKey that = (SoftwareKey) o;
            return uid == that.uid && Objects.equals(alias, that.alias);
        }
        
        @Override
        public int hashCode() {
            return Objects.hash(uid, alias);
        }
        
        @Override
        public String toString() {
            return "SoftwareKey{uid=" + uid + ", alias='" + alias + "'}";
        }
    }

    /**
     * Software key entry holding keypair, certificates, and metadata.
     * Based on TrickyStoreOSS SecurityLevelInterceptor.Info
     * @hide
     */
    public static final class SoftwareKeyEntry {
        public final KeyPair keyPair;
        public final List<Certificate> certificateChain;
        public final int algorithm; // KM_ALGORITHM_EC or KM_ALGORITHM_RSA
        public final int keySize;
        public final int[] purposes;
        public final int[] digests;
        public final int[] paddings;
        public final int[] blockModes;
        public final int[] mgf1Digests;
        public final long creationTime;
        public final Long validityStart;
        public final Long validityEndOrigination;
        public final Long validityEndConsumption;
        public final Integer maxUsageCount;
        public volatile int usageRemaining;
        
        public SoftwareKeyEntry(
                KeyPair keyPair,
                List<Certificate> certificateChain,
                int algorithm,
                int keySize,
                int[] purposes,
                int[] digests,
                int[] paddings,
                int[] blockModes,
                int[] mgf1Digests,
                Long validityStart,
                Long validityEndOrigination,
                Long validityEndConsumption,
                Integer maxUsageCount) {
            this.keyPair = keyPair;
            this.certificateChain = certificateChain;
            this.algorithm = algorithm;
            this.keySize = keySize;
            this.purposes = purposes != null ? purposes : new int[0];
            this.digests = digests != null ? digests : new int[0];
            this.paddings = paddings != null ? paddings : new int[0];
            this.blockModes = blockModes != null ? blockModes : new int[0];
            this.mgf1Digests = mgf1Digests != null ? mgf1Digests : new int[0];
            this.creationTime = System.currentTimeMillis();
            this.validityStart = validityStart;
            this.validityEndOrigination = validityEndOrigination;
            this.validityEndConsumption = validityEndConsumption;
            this.maxUsageCount = maxUsageCount;
            this.usageRemaining = maxUsageCount != null ? maxUsageCount : -1;
        }
        
        public PrivateKey getPrivateKey() {
            return keyPair.getPrivate();
        }
        
        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }
        
        public boolean hasUsageLimit() {
            return maxUsageCount != null && maxUsageCount > 0;
        }
        
        public boolean consumeUsage() {
            if (!hasUsageLimit()) return true;
            synchronized (this) {
                if (usageRemaining <= 0) return false;
                usageRemaining--;
                return true;
            }
        }
    }

    /**
     * Grant info for software keys.
     * Based on TrickyStoreOSS Keystore2Interceptor.GrantInfo
     * @hide
     */
    public static final class GrantInfo {
        public final long grantId;
        public final SoftwareKey originalKey;
        public final int granteeUid;
        
        public GrantInfo(long grantId, SoftwareKey originalKey, int granteeUid) {
            this.grantId = grantId;
            this.originalKey = originalKey;
            this.granteeUid = granteeUid;
        }
    }

    // Software key storage - keys are kept in memory, never touch real keystore
    // Based on TrickyStoreOSS architecture
    private final Map<SoftwareKey, SoftwareKeyEntry> mSoftwareKeys = new ConcurrentHashMap<>();
    private final Map<SoftwareKey, KeyEntryResponse> mCachedResponses = new ConcurrentHashMap<>();
    private final Map<SoftwareKey, Long> mKeyNspaces = new ConcurrentHashMap<>();
    private final Map<Long, SoftwareKey> mNspaceToKey = new ConcurrentHashMap<>();
    private final Map<Long, GrantInfo> mGrants = new ConcurrentHashMap<>();
    private final AtomicLong mNextGrantId = new AtomicLong(0x7F000000_00000000L); // High bits to avoid collision
    private final Random mRandom = new Random();

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
        mKeyBoxManager = new KeyBoxManager();
    }

    public static synchronized TrickyStoreService getInstance() {
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
        // Eagerly warm up TEE status in the background so isTeeBroken() never
        // returns a stale null when the settings UI reads it at startup.
        new Thread(() -> {
            try {
                ensureTeeStatus();
            } catch (Exception e) {
                Log.w(TAG, "Background TEE check failed", e);
            }
        }, "TrickyStore-TeeInit").start();
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
                  ", generate=" + mGeneratePackages + ", modes=" + mPackageModes);
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
            }
            reader.endArray();
        }
    }

    public void refreshKeyBox() {
        String raw = fetchFromAms(am -> am.getSpoofTrickyStoreKeyBox());
        if (raw == null || raw.isEmpty()) {
            mKeyBoxManager.clear();
            mLastKeyboxFingerprint = null;
            return;
        }
        String fingerprint = Integer.toHexString(raw.hashCode()) + ":" + raw.length();
        if (fingerprint.equals(mLastKeyboxFingerprint)) {
            return;
        }
        String xml = decodeKeybox(raw);
        if (xml == null) {
            Log.e(TAG, "Keybox payload not recognised as XML or base64-encoded XML");
            return;
        }
        try {
            if (!isValidKeyboxXml(xml)) {
                mLastKeyboxFingerprint = null;
                Log.e(TAG, "Keybox XML failed structural validation (missing keys or identifier)");
                return;
            }
            checkKeyboxRevocation(xml);
            mKeyBoxManager.parseKeybox(xml);
            if (mKeyBoxManager.hasKeyboxes()) {
                mLastKeyboxFingerprint = fingerprint;
                Log.i(TAG, "Keybox updated successfully");
            } else {
                mLastKeyboxFingerprint = null;
                Log.e(TAG, "Keybox parse produced no usable entries");
            }
        } catch (Exception e) {
            mLastKeyboxFingerprint = null;
            Log.e(TAG, "Failed to update keybox", e);
        }
    }

    private String decodeKeybox(String payload) {
        String trimmed = payload.trim();
        if (trimmed.startsWith("<")) {
            return trimmed;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(trimmed);
            String asXml = new String(decoded, StandardCharsets.UTF_8).trim();
            if (asXml.startsWith("<")) {
                return asXml;
            }
        } catch (IllegalArgumentException ignored) {
        }
        return null;
    }

    public void refreshPatchLevel() {
        String content = fetchFromAms(am -> am.getSpoofTrickyStorePatch());
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
        StringBuilder filtered = new StringBuilder();
        for (String raw : content.split("\n")) {
            String line = raw.trim();
            if (!line.isEmpty() && !line.startsWith("#")) {
                filtered.append(line).append("\n");
            }
        }

        String lines = filtered.toString().trim();
        if (lines.isEmpty()) {
            mCustomPatchLevel = null;
            return;
        }

        String[] parts = lines.split("\n");
        if (parts.length == 1 && !parts[0].contains("=")) {
            mCustomPatchLevel = new CustomPatchLevel(parts[0], parts[0], parts[0], parts[0]);
            return;
        }

        String system = null, vendor = null, boot = null, all = null;
        for (String part : parts) {
            int idx = part.indexOf('=');
            if (idx > 0) {
                String key = part.substring(0, idx).trim().toLowerCase();
                String value = part.substring(idx + 1).trim();
                switch (key) {
                    case "system": system = value; break;
                    case "vendor": vendor = value; break;
                    case "boot": boot = value; break;
                    case "all": all = value; break;
                }
            }
        }
        mCustomPatchLevel = new CustomPatchLevel(
            system != null ? system : all,
            vendor != null ? vendor : all,
            boot != null ? boot : all,
            all
        );
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
                    case "boot": boot = reader.nextString(); break;
                    case "all": all = reader.nextString(); break;
                    default: reader.skipValue(); break;
                }
            }
            reader.endObject();
        }
        mCustomPatchLevel = new CustomPatchLevel(
            system != null ? system : all,
            vendor != null ? vendor : all,
            boot != null ? boot : all,
            all
        );
    }

    private void ensureTeeStatus() {
        if (mTeeBroken == null) {
            synchronized (this) {
                if (mTeeBroken == null) {
                    mTeeBroken = checkTeeBroken();
                    if (mTeeBroken) {
                        AttestationUtils.setTeeBroken(true);
                    }
                }
            }
        }
    }

    private boolean isValidKeyboxXml(String xml) {
        boolean hasEcdsa = xml.contains("<Key algorithm=\"ecdsa\">");
        boolean hasRsa = xml.contains("<Key algorithm=\"rsa\">");
        boolean hasId = xml.contains("<serial>") || xml.contains("DeviceID");
        if (!hasEcdsa && !hasRsa) {
            Log.e(TAG, "Keybox validation failed: no ECDSA or RSA key block found");
            return false;
        }
        if (!hasId) {
            Log.e(TAG, "Keybox validation failed: no identifier field (serial/DeviceID)");
            return false;
        }
        if (!hasEcdsa) Log.w(TAG, "Keybox warning: missing ECDSA key block");
        if (!hasRsa)   Log.w(TAG, "Keybox warning: missing RSA key block");
        return true;
    }

    private void checkKeyboxRevocation(String xml) {
        long now = System.currentTimeMillis();
        if (now - mLastRevocationCheckMs < REVOCATION_CHECK_COOLDOWN_MS) {
            Log.d(TAG, "Skipping revocation check — ran within 24h");
            return;
        }
        mLastRevocationCheckMs = now;
        new Thread(() -> {
            try {
                List<String> serials = extractCertSerials(xml);
                if (serials.isEmpty()) return;
                java.net.URL url = new java.net.URL(
                        "https://android.googleapis.com/attestation/status");
                java.net.HttpURLConnection conn =
                        (java.net.HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(10_000);
                conn.setReadTimeout(10_000);
                if (conn.getResponseCode() != java.net.HttpURLConnection.HTTP_OK) return;
                String body = new String(
                        conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
                org.json.JSONObject entries =
                        new org.json.JSONObject(body).optJSONObject("entries");
                if (entries == null) return;
                for (String serial : serials) {
                    org.json.JSONObject entry = entries.optJSONObject(serial);
                    if (entry == null) continue;
                    String status = entry.optString("status", "").toUpperCase(java.util.Locale.US);
                    if ("REVOKED".equals(status) || "SUSPENDED".equals(status)) {
                        Log.w(TAG, "Keybox serial " + serial + " is " + status +
                                " — attestation may fail");
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Keybox revocation check failed", e);
            }
        }, "TrickyStore-RevocationCheck").start();
    }

    private List<String> extractCertSerials(String xml) {
        List<String> serials = new ArrayList<>();
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(
                "-----BEGIN CERTIFICATE-----([\\s\\S]+?)-----END CERTIFICATE-----");
        java.util.regex.Matcher m = p.matcher(xml);
        java.security.cert.CertificateFactory factory;
        try {
            factory = java.security.cert.CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            return serials;
        }
        while (m.find()) {
            try {
                byte[] der = Base64.getDecoder().decode(
                        m.group(1).replaceAll("\\s", ""));
                java.security.cert.X509Certificate cert =
                        (java.security.cert.X509Certificate)
                        factory.generateCertificate(
                                new java.io.ByteArrayInputStream(der));
                serials.add(cert.getSerialNumber().toString(16).toUpperCase(java.util.Locale.US));
            } catch (Exception ignored) {}
        }
        return serials;
    }

    private boolean checkTeeBroken() {
        try {
            String alias = "TrickyStoreTeeCheck";
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(new byte[16]);

            kpg.initialize(builder.build());
            kpg.generateKeyPair();

            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            ks.deleteEntry(alias);

            Log.i(TAG, "TEE verification successful");
            return false;
        } catch (Exception e) {
            Log.w(TAG, "TEE verification failed, TEE is broken", e);
            return true;
        }
    }

    public boolean needHack(int callingUid, String[] packages) {
        if (packages == null) return false;
        refreshTargets();
        ensureTeeStatus();
        for (String pkg : packages) {
            Mode mode = mPackageModes.get(pkg);
            if (mode == Mode.LEAF_HACK) return true;
            if (mode == Mode.AUTO && !mTeeBroken) return true;
        }
        return false;
    }

    public boolean needGenerate(int callingUid, String[] packages) {
        if (packages == null) return false;
        refreshTargets();
        ensureTeeStatus();
        for (String pkg : packages) {
            Mode mode = mPackageModes.get(pkg);
            if (mode == Mode.GENERATE) return true;
            if (mode == Mode.AUTO && mTeeBroken) return true;
        }
        return false;
    }

    public KeyBoxManager getKeyBoxManager() {
        refreshKeyBox();
        return mKeyBoxManager;
    }

    public CustomPatchLevel getCustomPatchLevel() {
        refreshPatchLevel();
        return mCustomPatchLevel;
    }

    public boolean hasKeyboxes() {
        return mKeyBoxManager.hasKeyboxes();
    }

    /**
     * Returns whether the TEE is broken, forcing the check if it hasn't run yet.
     * Safe to call from any thread; the underlying check is synchronized.
     */
    public boolean isTeeBroken() {
        ensureTeeStatus();
        return Boolean.TRUE.equals(mTeeBroken);
    }

    // ============================================================================
    // Software Key Management - TrickyStoreOSS-style in-memory key storage
    // Keys are generated in software and never imported into real keystore.
    // Operations are handled entirely in software via SoftwareOperationBinder.
    // ============================================================================

    /**
     * Store a software-generated key. Called instead of importKey for forged keys.
     * @return the SoftwareKey identifier
     */
    public SoftwareKey storeSoftwareKey(int uid, String alias, SoftwareKeyEntry entry) {
        SoftwareKey key = new SoftwareKey(uid, alias);
        mSoftwareKeys.put(key, entry);
        Log.d(TAG, "Stored software key: " + key);
        return key;
    }

    /**
     * Get a software key entry by uid and alias.
     * @return the entry, or null if not found
     */
    public SoftwareKeyEntry getSoftwareKey(int uid, String alias) {
        return mSoftwareKeys.get(new SoftwareKey(uid, alias));
    }

    /**
     * Check if a software key exists.
     */
    public boolean hasSoftwareKey(int uid, String alias) {
        return mSoftwareKeys.containsKey(new SoftwareKey(uid, alias));
    }

    /**
     * Delete a software key.
     * @return true if the key existed and was deleted
     */
    public boolean deleteSoftwareKey(int uid, String alias) {
        SoftwareKey key = new SoftwareKey(uid, alias);
        SoftwareKeyEntry removed = mSoftwareKeys.remove(key);
        if (removed != null) {
            // Also remove any grants for this key
            mGrants.values().removeIf(grant -> grant.originalKey.equals(key));
            Log.d(TAG, "Deleted software key: " + key);
            return true;
        }
        return false;
    }

    /**
     * List all software key aliases for a given uid.
     */
    public List<String> listSoftwareKeyAliases(int uid) {
        List<String> aliases = new ArrayList<>();
        for (SoftwareKey key : mSoftwareKeys.keySet()) {
            if (key.uid == uid) {
                aliases.add(key.alias);
            }
        }
        return aliases;
    }

    /**
     * Grant access to a software key.
     * @return the grant ID
     */
    public long grantSoftwareKey(int ownerUid, String alias, int granteeUid) {
        SoftwareKey originalKey = new SoftwareKey(ownerUid, alias);
        if (!mSoftwareKeys.containsKey(originalKey)) {
            throw new IllegalArgumentException("Software key not found: " + originalKey);
        }
        long grantId = mNextGrantId.getAndIncrement();
        mGrants.put(grantId, new GrantInfo(grantId, originalKey, granteeUid));
        Log.d(TAG, "Granted software key access: grantId=" + grantId + 
              ", key=" + originalKey + ", grantee=" + granteeUid);
        return grantId;
    }

    /**
     * Revoke a grant.
     */
    public void ungrantSoftwareKey(long grantId) {
        GrantInfo removed = mGrants.remove(grantId);
        if (removed != null) {
            Log.d(TAG, "Revoked software key grant: " + grantId);
        }
    }

    /**
     * Get a software key entry via grant.
     * @return the entry, or null if grant not found or invalid
     */
    public SoftwareKeyEntry getSoftwareKeyByGrant(long grantId, int callerUid) {
        GrantInfo grant = mGrants.get(grantId);
        if (grant == null) {
            return null;
        }
        if (grant.granteeUid != callerUid) {
            Log.w(TAG, "Grant " + grantId + " not valid for uid " + callerUid);
            return null;
        }
        return mSoftwareKeys.get(grant.originalKey);
    }

    /**
     * Get the original key for a grant (for certificate chain updates, etc).
     */
    public SoftwareKey getGrantOriginalKey(long grantId) {
        GrantInfo grant = mGrants.get(grantId);
        return grant != null ? grant.originalKey : null;
    }

    /**
     * Update the certificate chain for a software key.
     */
    public void updateSoftwareKeyCertificates(int uid, String alias, List<Certificate> newChain) {
        SoftwareKey key = new SoftwareKey(uid, alias);
        SoftwareKeyEntry existing = mSoftwareKeys.get(key);
        if (existing == null) {
            Log.w(TAG, "Cannot update certificates - key not found: " + key);
            return;
        }
        // Create new entry with updated chain (entry is effectively immutable otherwise)
        SoftwareKeyEntry updated = new SoftwareKeyEntry(
            existing.keyPair,
            newChain,
            existing.algorithm,
            existing.keySize,
            existing.purposes,
            existing.digests,
            existing.paddings,
            existing.blockModes,
            existing.mgf1Digests,
            existing.validityStart,
            existing.validityEndOrigination,
            existing.validityEndConsumption,
            existing.maxUsageCount
        );
        mSoftwareKeys.put(key, updated);
        Log.d(TAG, "Updated software key certificates: " + key);
    }

    /**
     * Clear all software keys. Used during testing or reset.
     */
    public void clearAllSoftwareKeys() {
        mSoftwareKeys.clear();
        mCachedResponses.clear();
        mKeyNspaces.clear();
        mNspaceToKey.clear();
        mGrants.clear();
        Log.i(TAG, "Cleared all software keys and grants");
    }

    /**
     * Get or build a KeyEntryResponse for a software key.
     * This is what AndroidKeyStoreSpi.getKeyMetadata returns for software keys.
     */
    public KeyEntryResponse getKeyEntryResponse(int uid, String alias, 
            KeyStoreSecurityLevel securityLevel, int securityLevelValue) {
        SoftwareKey key = new SoftwareKey(uid, alias);
        
        // Check cache first
        KeyEntryResponse cached = mCachedResponses.get(key);
        if (cached != null) {
            return cached;
        }
        
        SoftwareKeyEntry entry = mSoftwareKeys.get(key);
        if (entry == null) {
            return null;
        }
        
        KeyEntryResponse response = buildKeyEntryResponse(key, entry, securityLevel, securityLevelValue);
        mCachedResponses.put(key, response);
        return response;
    }
    
    /**
     * Build a synthetic KeyEntryResponse for a software key.
     * Based on TrickyStoreOSS SecurityLevelInterceptor.buildResponse
     */
    private KeyEntryResponse buildKeyEntryResponse(SoftwareKey key, SoftwareKeyEntry entry,
            KeyStoreSecurityLevel securityLevel, int securityLevelValue) {
        
        KeyEntryResponse response = new KeyEntryResponse();
        KeyMetadata metadata = new KeyMetadata();
        
        // Set security level
        metadata.keySecurityLevel = securityLevelValue;
        metadata.modificationTimeMs = entry.creationTime / 1000;
        
        // Build certificate chain bytes
        List<Certificate> chain = entry.certificateChain;
        if (chain != null && !chain.isEmpty()) {
            try {
                metadata.certificate = chain.get(0).getEncoded();
                if (chain.size() > 1) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    for (int i = 1; i < chain.size(); i++) {
                        baos.write(chain.get(i).getEncoded());
                    }
                    metadata.certificateChain = baos.toByteArray();
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to encode certificate chain", e);
            }
        }
        
        // Build key descriptor with unique nspace
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.domain = 4; // KEY_ID domain
        
        // Get or create nspace for this key
        Long nspace = mKeyNspaces.get(key);
        if (nspace == null) {
            nspace = mRandom.nextLong();
            mKeyNspaces.put(key, nspace);
            mNspaceToKey.put(nspace, key);
        }
        descriptor.nspace = nspace;
        descriptor.alias = null;
        metadata.key = descriptor;
        
        // Build authorizations
        List<Authorization> authorizations = new ArrayList<>();
        
        // Algorithm
        addAuth(authorizations, Tag.ALGORITHM, KeyParameterValue.algorithm(entry.algorithm), securityLevelValue);
        
        // Purposes
        for (int purpose : entry.purposes) {
            addAuth(authorizations, Tag.PURPOSE, KeyParameterValue.keyPurpose(purpose), securityLevelValue);
        }
        
        // Digests
        for (int digest : entry.digests) {
            addAuth(authorizations, Tag.DIGEST, KeyParameterValue.digest(digest), securityLevelValue);
        }
        
        // Paddings
        for (int padding : entry.paddings) {
            addAuth(authorizations, Tag.PADDING, KeyParameterValue.paddingMode(padding), securityLevelValue);
        }
        
        // Block modes
        for (int blockMode : entry.blockModes) {
            addAuth(authorizations, Tag.BLOCK_MODE, KeyParameterValue.blockMode(blockMode), securityLevelValue);
        }
        
        // MGF digests
        for (int mgfDigest : entry.mgf1Digests) {
            addAuth(authorizations, Tag.RSA_OAEP_MGF_DIGEST, KeyParameterValue.digest(mgfDigest), securityLevelValue);
        }
        
        // Key size
        addAuth(authorizations, Tag.KEY_SIZE, KeyParameterValue.integer(entry.keySize), securityLevelValue);
        
        // No auth required (software keys don't need auth)
        addAuth(authorizations, Tag.NO_AUTH_REQUIRED, KeyParameterValue.boolValue(true), securityLevelValue);
        
        // Origin - claim TEE generated
        addAuth(authorizations, Tag.ORIGIN, KeyParameterValue.origin(0), securityLevelValue); // 0 = GENERATED
        
        // OS/patch levels from AttestationUtils
        int osVersion = AttestationUtils.getOsVersion();
        int patchLevel = AttestationUtils.getPatchLevel(false);
        
        addAuth(authorizations, Tag.OS_VERSION, KeyParameterValue.integer(osVersion), securityLevelValue);
        addAuth(authorizations, Tag.OS_PATCHLEVEL, KeyParameterValue.integer(patchLevel), securityLevelValue);
        
        // Creation datetime (software level)
        addAuth(authorizations, Tag.CREATION_DATETIME, KeyParameterValue.dateTime(entry.creationTime), 0);
        
        // Validity dates (software level)
        if (entry.validityStart != null) {
            addAuth(authorizations, Tag.ACTIVE_DATETIME, KeyParameterValue.dateTime(entry.validityStart), 0);
        }
        if (entry.validityEndOrigination != null) {
            addAuth(authorizations, Tag.ORIGINATION_EXPIRE_DATETIME, 
                    KeyParameterValue.dateTime(entry.validityEndOrigination), 0);
        }
        if (entry.validityEndConsumption != null) {
            addAuth(authorizations, Tag.USAGE_EXPIRE_DATETIME,
                    KeyParameterValue.dateTime(entry.validityEndConsumption), 0);
        }
        
        // Usage count limit (software level)
        if (entry.maxUsageCount != null && entry.maxUsageCount > 0) {
            addAuth(authorizations, Tag.USAGE_COUNT_LIMIT, 
                    KeyParameterValue.integer(entry.maxUsageCount), 0);
        }
        
        metadata.authorizations = authorizations.toArray(new Authorization[0]);
        
        response.metadata = metadata;
        response.iSecurityLevel = securityLevel.asBinder();
        
        return response;
    }
    
    private void addAuth(List<Authorization> list, int tag, KeyParameterValue value, int secLevel) {
        Authorization auth = new Authorization();
        KeyParameter param = new KeyParameter();
        param.tag = tag;
        param.value = value;
        auth.keyParameter = param;
        auth.securityLevel = secLevel;
        list.add(auth);
    }
    
    /**
     * Resolve a software key from a nspace (for grants/lookups).
     */
    public SoftwareKey getSoftwareKeyByNspace(long nspace) {
        return mNspaceToKey.get(nspace);
    }
    
    /**
     * Get the nspace for a software key.
     */
    public Long getNspaceForSoftwareKey(int uid, String alias) {
        return mKeyNspaces.get(new SoftwareKey(uid, alias));
    }
}

