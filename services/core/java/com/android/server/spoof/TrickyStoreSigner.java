/*
 * Copyright (C) 2026 CharaROM
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.server.spoof;

import android.content.Context;
import android.os.Binder;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.os.UserHandle;
import android.provider.Settings;
import android.security.trickystore.CertificateGenerator.KeyGenParameters;
import android.security.trickystore.KeyBoxManager;
import android.security.trickystore.TrickyStoreService;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** System-only owner of imported attestation issuer keys. No private key IPC. */
public final class TrickyStoreSigner {
    private static final int MAX_CONFIG = 1024 * 1024;
    private static final int MAX_PUBLIC_KEY = 2048;
    private static final ThreadLocal<Context> CONTEXT = new ThreadLocal<>();
    private static final java.util.concurrent.Semaphore WORK = new java.util.concurrent.Semaphore(4);
    private static final Map<Integer, Integer> ACTIVE = new HashMap<>();
    private static final class CacheEntry {
        final String raw;
        final KeyBoxManager manager;
        CacheEntry(String raw, KeyBoxManager manager) { this.raw = raw; this.manager = manager; }
    }
    // Exact configuration equality, partitioned by user; removal/replacement never
    // falls back to an older key. Bounded to eight active user configurations.
    private static final java.util.LinkedHashMap<Integer, CacheEntry> CACHE =
            new java.util.LinkedHashMap<>(8, 0.75f, true);

    private static synchronized KeyBoxManager load(int user, String raw) {
        if (raw == null || raw.isEmpty()) { CACHE.remove(user); return null; }
        CacheEntry hit = CACHE.get(user);
        if (hit != null && hit.raw.equals(raw)) return hit.manager;
        CACHE.remove(user);
        String xml = raw.trim();
        if (!xml.startsWith("<")) xml = new String(Base64.getDecoder().decode(xml), StandardCharsets.UTF_8).trim();
        KeyBoxManager manager = new KeyBoxManager();
        if (!manager.parseKeybox(xml) || !manager.hasKeyboxes()) return null;
        if (CACHE.size() >= 8) CACHE.remove(CACHE.keySet().iterator().next());
        CACHE.put(user, new CacheEntry(raw, manager));
        return manager;
    }

    private static final Set<String> FIELDS = Set.of(
            "level", "challenge", "purpose", "digest", "padding",
            "subject", "serial", "notBefore", "notAfter", "mgfDigest");

    private TrickyStoreSigner() {}

    static Context currentContext() { return CONTEXT.get(); }

    // Request-local fallback: never probes TEE, calls app hooks, or caches a user's issuer.
    static byte[] bootDigest(boolean hash) throws Exception {
        String prop = android.os.SystemProperties.get(hash ? "ro.boot.vbmeta.digest"
                : "ro.boot.vbmeta.public_key_digest", "");
        if (prop.matches("[0-9a-fA-F]{64}")) {
            byte[] bytes = new byte[32];
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) Integer.parseInt(prop.substring(i * 2, i * 2 + 2), 16);
            }
            return bytes;
        }
        KeyBoxManager manager = TrickyStoreService.getInstance().getKeyBoxManager();
        KeyBoxManager.KeyBox box = manager.getKeybox("EC");
        if (box == null) box = manager.getKeybox("RSA");
        if (box == null) throw new IllegalStateException("No issuer");
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        if (hash) digest.update("boothash".getBytes(StandardCharsets.UTF_8));
        return digest.digest(box.certificates.get(0).getEncoded());
    }

    private static synchronized boolean acquire(int uid) {
        int active = ACTIVE.getOrDefault(uid, 0);
        if (active >= 2 || !WORK.tryAcquire()) return false;
        ACTIVE.put(uid, active + 1);
        return true;
    }

    private static synchronized void release(int uid) {
        int active = ACTIVE.getOrDefault(uid, 0);
        if (active <= 1) ACTIVE.remove(uid); else ACTIVE.put(uid, active - 1);
        WORK.release();
    }

    /** Capture caller identity before clearing it, never accept package/user arguments. */
    public static byte[] sign(Context context, byte[] publicKey, String algorithm, Bundle metadata) {
        final int uid = Binder.getCallingUid();
        if (Process.isIsolated(uid) || publicKey == null || publicKey.length == 0
                || publicKey.length > MAX_PUBLIC_KEY || metadata == null) {
            return null;
        }
        if (!"EC".equals(algorithm) && !"RSA".equals(algorithm)) return null;
        final int userId = UserHandle.getUserId(uid);
        final String[] packages = context.getPackageManager().getPackagesForUid(uid);
        if (packages == null || packages.length == 0 || packages.length > 64) return null;
        if (!acquire(uid)) return null;
        final long identity = Binder.clearCallingIdentity();
        try {
            Context callerContext = context.createContextAsUser(UserHandle.of(userId), 0);
            CONTEXT.set(callerContext);
            if (!configure(callerContext, userId, packages)) return null;
            Bundle.setDefusable(metadata, true);
            if (metadata.size() > FIELDS.size() || !FIELDS.containsAll(metadata.keySet())) return null;
            // No StrongBox support. Never relabel a software issuer as StrongBox.
            if (metadata.getInt("level", -1) != 1) return null;
            byte[] challenge = metadata.getByteArray("challenge");
            if (challenge == null || challenge.length == 0 || challenge.length > 128) return null;
            PublicKey key = KeyFactory.getInstance(algorithm)
                    .generatePublic(new X509EncodedKeySpec(publicKey));
            KeyGenParameters p = new KeyGenParameters();
            p.attestationChallenge = challenge.clone();
            p.packages = packages;
            byte[] subject = metadata.getByteArray("subject");
            byte[] serial = metadata.getByteArray("serial");
            if (subject != null) {
                if (subject.length == 0 || subject.length > 1024) return null;
                p.certificateSubject = new javax.security.auth.x500.X500Principal(subject);
            }
            if (serial != null) {
                if (serial.length == 0 || serial.length > 20) return null;
                p.certificateSerial = new java.math.BigInteger(serial);
                if (p.certificateSerial.signum() <= 0) return null;
            }
            if (metadata.containsKey("notBefore")) p.certificateNotBefore = new java.util.Date(metadata.getLong("notBefore"));
            if (metadata.containsKey("notAfter")) p.certificateNotAfter = new java.util.Date(metadata.getLong("notAfter"));
            if (p.certificateNotBefore != null && p.certificateNotAfter != null
                    && p.certificateNotAfter.before(p.certificateNotBefore)) return null;
            p.purpose = integers(metadata, "purpose", Set.of(0, 1, 2, 3, 5, 6));
            p.digest = integers(metadata, "digest", Set.of(0, 1, 2, 3, 4, 5, 6));
            p.padding = integers(metadata, "padding", Set.of(1, 2, 3, 4, 5, 64));
            p.rsaOaepMgfDigest = integers(metadata, "mgfDigest", Set.of(2, 3, 4, 5, 6));
            if (key instanceof ECPublicKey) {
                ECPublicKey ec = (ECPublicKey) key;
                p.algorithm = 3;
                p.keySize = ec.getParams().getCurve().getField().getFieldSize();
                if (p.keySize == 256) p.ecCurve = 1;
                else if (p.keySize == 384) p.ecCurve = 2;
                else if (p.keySize == 521) p.ecCurve = 3;
                else return null;
            } else if (key instanceof RSAPublicKey) {
                RSAPublicKey rsa = (RSAPublicKey) key;
                p.algorithm = 1;
                p.keySize = rsa.getModulus().bitLength();
                if (p.keySize < 2048 || p.keySize > 4096) return null;
                p.rsaPublicExponent = rsa.getPublicExponent();
                if (!java.security.spec.RSAKeyGenParameterSpec.F4.equals(p.rsaPublicExponent)) return null;
            } else return null;
            List<java.security.cert.Certificate> chain =
                    TrickyStoreCertificateGenerator.generateCertificateChain(
                            new KeyPair(key, null), p, 1, uid);
            if (chain == null || chain.size() > 8) return null;
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            for (java.security.cert.Certificate cert : chain) {
                byte[] der = cert.getEncoded();
                if (der.length > 16384 || result.size() + der.length > 65536) return null;
                result.write(der);
            }
            return result.toByteArray();
        } catch (Exception e) {
            // Imported keys, certificate subjects and parser exceptions are not logs.
            return null;
        } finally {
            TrickyStoreService.setServerConfig(null, null, null);
            CONTEXT.remove();
            Binder.restoreCallingIdentity(identity);
            release(uid);
        }
    }

    public static byte[] rewrite(Context context, byte[] encoded) {
        final int uid = Binder.getCallingUid();
        if (Process.isIsolated(uid) || encoded == null || encoded.length > 65536
                || encoded.length == 0) return null;
        final int userId = UserHandle.getUserId(uid);
        final String[] packages = context.getPackageManager().getPackagesForUid(uid);
        if (packages == null || packages.length == 0 || packages.length > 64 || !acquire(uid)) return null;
        final long identity = Binder.clearCallingIdentity();
        try {
            Context callerContext = context.createContextAsUser(UserHandle.of(userId), 0);
            CONTEXT.set(callerContext);
            if (!configure(callerContext, userId, packages)) return null;
            var factory = java.security.cert.CertificateFactory.getInstance("X.509");
            var input = factory.generateCertificates(new java.io.ByteArrayInputStream(encoded));
            if (input.isEmpty() || input.size() > 8) return null;
            var chain = input.toArray(new java.security.cert.Certificate[0]);
            var leaf = (java.security.cert.X509Certificate) chain[0];
            if (leaf.getBasicConstraints() >= 0) return null;
            for (int i = 0; i < chain.length; i++) {
                var cert = (java.security.cert.X509Certificate) chain[i];
                if (cert.getEncoded().length > 16384) return null;
                cert.checkValidity();
                if (i + 1 < chain.length) cert.verify(chain[i + 1].getPublicKey());
            }
            // Pin the original hardware path to an explicitly imported issuer trust
            // anchor. A different OEM/Google root is unsupported, not blindly trusted.
            KeyBoxManager manager = TrickyStoreService.getInstance().getKeyBoxManager();
            boolean trusted = false;
            for (String alg : new String[] {"EC", "RSA"}) {
                var box = manager.getKeybox(alg);
                if (box == null) continue;
                var anchor = box.certificates.get(box.certificates.size() - 1);
                try {
                    var last = chain[chain.length - 1];
                    if (java.util.Arrays.equals(last.getEncoded(), anchor.getEncoded())) trusted = true;
                    else { last.verify(anchor.getPublicKey()); trusted = true; }
                } catch (java.security.GeneralSecurityException ignored) { }
            }
            if (!trusted) return null;
            var holder = new com.android.internal.org.bouncycastle.cert.X509CertificateHolder(leaf.getEncoded());
            var ext = holder.getExtension(android.security.trickystore.CertificateGenerator.ATTESTATION_OID);
            if (ext == null) return null;
            var seq = com.android.internal.org.bouncycastle.asn1.ASN1Sequence.getInstance(ext.getExtnValue().getOctets());
            if (seq.size() != 8) return null;
            if (com.android.internal.org.bouncycastle.asn1.ASN1Enumerated.getInstance(seq.getObjectAt(1)).intValueExact() != 1
                    || com.android.internal.org.bouncycastle.asn1.ASN1Enumerated.getInstance(seq.getObjectAt(3)).intValueExact() != 1) return null;
            byte[] challenge = com.android.internal.org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets();
            if (challenge.length == 0 || challenge.length > 128) return null;
            var sw = com.android.internal.org.bouncycastle.asn1.ASN1Sequence.getInstance(seq.getObjectAt(6));
            boolean appIdMatches = false;
            for (var item : sw) {
                var tag = com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject.getInstance(item);
                if (tag.getTagNo() == 709) {
                    if (appIdMatches) return null; // duplicate authorization
                    var value = com.android.internal.org.bouncycastle.asn1.ASN1OctetString.getInstance(tag.getBaseObject());
                    appIdMatches = java.util.Arrays.equals(value.getOctets(),
                        TrickyStoreCertificateGenerator.createApplicationId(uid).getOctets());
                    if (!appIdMatches) return null;
                }
            }
            if (!appIdMatches) return null;
            var result = TrickyStoreCertificateHacker.hackCertificateChain(chain, packages);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (var cert : result) {
                byte[] der = cert.getEncoded();
                if (der.length > 16384 || out.size() + der.length > 65536) return null;
                out.write(der);
            }
            return out.toByteArray();
        } catch (Throwable e) {
            return null;
        } finally {
            TrickyStoreService.setServerConfig(null, null, null);
            CONTEXT.remove();
            Binder.restoreCallingIdentity(identity);
            release(uid);
        }
    }

    private static List<Integer> integers(Bundle b, String field, Set<Integer> permitted) {
        ArrayList<Integer> values = b.getIntegerArrayList(field);
        if (values == null) return new ArrayList<>();
        if (values.size() > 16 || !permitted.containsAll(values)) {
            throw new IllegalArgumentException("Unsupported key authorization");
        }
        return new ArrayList<>(new java.util.TreeSet<>(values));
    }

    public static boolean available(Context context) {
        final int uid = Binder.getCallingUid();
        if (Process.isIsolated(uid)) return false;
        final int userId = UserHandle.getUserId(uid);
        final String[] packages = context.getPackageManager().getPackagesForUid(uid);
        if (packages == null || packages.length == 0 || packages.length > 64) return false;
        if (!acquire(uid)) return false;
        final long identity = Binder.clearCallingIdentity();
        try {
            return configure(context.createContextAsUser(UserHandle.of(userId), 0), userId, packages);
        } catch (Exception e) {
            return false;
        } finally {
            TrickyStoreService.setServerConfig(null, null, null);
            Binder.restoreCallingIdentity(identity);
            release(uid);
        }
    }

    private static String setting(Context context, String name, int user) {
        String value = Settings.Secure.getStringForUser(context.getContentResolver(), name, user);
        if (value != null && value.length() > MAX_CONFIG) {
            throw new IllegalArgumentException("Configuration too large");
        }
        return value;
    }

    private static boolean configure(Context context, int userId, String[] packages) {
        String targets = setting(context, Settings.Secure.SPOOF_TRICKYSTORE_TARGET, userId);
        String patch = setting(context, Settings.Secure.SPOOF_TRICKYSTORE_PATCH, userId);
        KeyBoxManager manager = new KeyBoxManager();
        TrickyStoreService.setServerConfig(targets, patch, manager);
        TrickyStoreService config = TrickyStoreService.getInstance();
        // Shared UID callers cannot inherit a target's rights through an excluded sibling.
        for (String pkg : packages) {
            TrickyStoreService.Mode mode = config.configuredMode(pkg);
            if (mode == null || mode == TrickyStoreService.Mode.SKIP
                    || TrickyStoreService.XPOSED_PACKAGES.contains(pkg)) return false;
        }
        String raw = setting(context, Settings.Secure.SPOOF_TRICKYSTORE_KEYBOX, userId);
        if (raw == null || raw.isEmpty()) return false;
        manager = load(userId, raw);
        if (manager == null) return false;
        TrickyStoreService.setServerConfig(targets, patch, manager);
        return true;
    }
}
