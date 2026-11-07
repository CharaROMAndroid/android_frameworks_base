package android.security.trickystore;

import android.os.Build;
import android.os.SystemProperties;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.*;

import java.security.*;
import java.security.cert.*;

/**
 * @hide
 */
public final class AttestationUtils {
    private static final String TAG = "AttestationUtils";

    private static byte[] sBootKey;
    private static byte[] sBootHash;
    private static volatile boolean sTeeBroken = false;

    private AttestationUtils() {}

    public static void setTeeBroken(boolean broken) {
        sTeeBroken = broken;
    }

    public static boolean isTeeBroken() {
        return sTeeBroken;
    }

    public static byte[] getBootKey() {
        if (sBootKey == null) {
            sBootKey = getBootKeyFromProp();
            if (sBootKey == null) {
                sBootKey = getBootKeyFromKeybox();
            }
            if (sBootKey == null) {
                Log.w(TAG, "No boot key from prop or keybox, using random bytes");
                sBootKey = generateRandomBytes(32);
            }
        }
        return sBootKey;
    }

    /**
     * Deterministic boot-hash fallback derived from the active keybox, used before
     * the random fallback so that — when the vbmeta prop is missing and the TEE is
     * broken — two attestations in the same boot still agree on RootOfTrust instead
     * of each getting fresh random bytes. Domain-separated from the boot KEY digest
     * (which is a plain SHA-256 of the same cert) so the two fields don't collide.
     * Returns null if no keybox is loaded.
     */
    private static byte[] deriveBootHashFromKeybox() {
        try {
            KeyBoxManager keyBoxManager = TrickyStoreService.getInstance().getKeyBoxManager();
            if (keyBoxManager == null || !keyBoxManager.hasKeyboxes()) {
                return null;
            }
            KeyBoxManager.KeyBox keybox = keyBoxManager.getKeybox("EC");
            if (keybox == null) {
                keybox = keyBoxManager.getKeybox("RSA");
            }
            if (keybox == null || keybox.certificates == null || keybox.certificates.isEmpty()) {
                return null;
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("boothash".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return digest.digest(keybox.certificates.get(0).getEncoded());
        } catch (Exception e) {
            Log.w(TAG, "Failed to derive boot hash from keybox", e);
            return null;
        }
    }

    /**
     * Derives a fallback verified-boot key from the active keybox's issuer certificate,
     * so that when the real vbmeta property is unavailable the attested key is at least
     * deterministic and tied to whatever keybox is actually signing the chain, rather than
     * an arbitrary persisted random value with no relation to anything else we attest.
     * Returns null if no keybox is currently loaded.
     */
    private static byte[] getBootKeyFromKeybox() {
        try {
            KeyBoxManager keyBoxManager = TrickyStoreService.getInstance().getKeyBoxManager();
            if (keyBoxManager == null || !keyBoxManager.hasKeyboxes()) {
                return null;
            }
            KeyBoxManager.KeyBox keybox = keyBoxManager.getKeybox("EC");
            if (keybox == null) {
                keybox = keyBoxManager.getKeybox("RSA");
            }
            if (keybox == null || keybox.certificates == null || keybox.certificates.isEmpty()) {
                return null;
            }
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(keybox.certificates.get(0).getEncoded());
        } catch (Exception e) {
            Log.w(TAG, "Failed to derive boot key from keybox issuer", e);
            return null;
        }
    }

    /**
     * Reads the real verified-boot public key digest from the bootloader property, so the
     * RootOfTrust key we attest matches the device's actual verified-boot chain instead of a
     * value with no relation to it. Falls back to the persisted random value only when the
     * property is unavailable.
     */
    private static byte[] getBootKeyFromProp() {
        String digest = SystemProperties.get("ro.boot.vbmeta.public_key_digest", null);
        if (digest == null || digest.isEmpty() || digest.length() != 64) {
            return null;
        }
        try {
            return hexStringToByteArray(digest);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse vbmeta.public_key_digest", e);
            return null;
        }
    }

    public static byte[] getBootHash() {
        if (sBootHash == null) {
            sBootHash = getBootHashFromProp();
            if (sBootHash == null && !sTeeBroken) {
                sBootHash = extractBootHashFromTee();
            }
            if (sBootHash == null) {
                sBootHash = deriveBootHashFromKeybox();
            }
            if (sBootHash == null) {
                Log.w(TAG, "Failed to get boot hash from prop, TEE, and keybox, using random bytes");
                sBootHash = generateRandomBytes(32);
            }
        }
        return sBootHash;
    }

    public static void initBootHash() {
        Log.i(TAG, "initBootHash: Starting boot hash initialization");
        byte[] hash = getBootHashFromProp();
        if (hash != null) {
            sBootHash = hash;
            Log.i(TAG, "initBootHash: Boot hash already set from prop: " + bytesToHex(hash));
            return;
        }
        Log.i(TAG, "initBootHash: No prop, attempting TEE extraction");
        hash = extractBootHashFromTee();
        if (hash != null) {
            sBootHash = hash;
            Log.i(TAG, "initBootHash: TEE extraction successful, setting prop");
            setVbmetaDigestProp(bytesToHex(hash));
        } else {
            Log.e(TAG, "initBootHash: Failed to extract boot hash from TEE");
        }
    }

    private static void setVbmetaDigestProp(String digest) {
        try {
            SystemProperties.set("ro.boot.vbmeta.digest", digest);
            Log.i(TAG, "Set ro.boot.vbmeta.digest property to TEE boot hash");
        } catch (Exception e) {
            Log.e(TAG, "Failed to set vbmeta.digest property", e);
        }
    }

    private static byte[] extractBootHashFromTee() {
        final String alias = "trickystore_attestation_key";
        KeyStore ks = null;
        boolean generated = false;
        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAttestationChallenge(new byte[32])
                    .build();
            kpg.initialize(spec);
            kpg.generateKeyPair();
            generated = true;

            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);

            if (chain == null || chain.length == 0) {
                Log.e(TAG, "No certificate chain from AndroidKeyStore");
                return null;
            }

            X509Certificate leafCert = (X509Certificate) chain[0];
            byte[] extValue = leafCert.getExtensionValue("1.3.6.1.4.1.11129.2.1.17");

            if (extValue == null) {
                Log.e(TAG, "No attestation extension in certificate");
                return null;
            }

            ASN1InputStream ais = new ASN1InputStream(extValue);
            ASN1OctetString octet = (ASN1OctetString) ais.readObject();
            ais.close();

            ASN1InputStream seqStream = new ASN1InputStream(octet.getOctets());
            ASN1Sequence keyDesc = (ASN1Sequence) seqStream.readObject();
            seqStream.close();

            ASN1Sequence teeEnforced = (ASN1Sequence) keyDesc.getObjectAt(7);

            for (int i = 0; i < teeEnforced.size(); i++) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) teeEnforced.getObjectAt(i);
                if (tagged.getTagNo() == 704) {
                    ASN1Sequence rootOfTrust = (ASN1Sequence) tagged.getBaseObject();
                    if (rootOfTrust.size() >= 4) {
                        ASN1OctetString bootHashOctet = (ASN1OctetString) rootOfTrust.getObjectAt(3);
                        byte[] hash = bootHashOctet.getOctets();
                        Log.i(TAG, "Extracted boot hash from TEE: " + bytesToHex(hash));
                        return hash;
                    }
                }
            }

            Log.e(TAG, "RootOfTrust not found in TEE enforced list");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "Failed to extract boot hash from TEE", e);
            return null;
        } finally {
            if (generated) {
                try {
                    if (ks == null) {
                        ks = KeyStore.getInstance("AndroidKeyStore");
                        ks.load(null);
                    }
                    ks.deleteEntry(alias);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to clean up TEE probe key", e);
                }
            }
        }
    }

    public static byte[] getBootHashFromProp() {
        String digest = SystemProperties.get("ro.boot.vbmeta.digest", null);
        if (digest == null || digest.isEmpty() || digest.length() != 64) {
            return null;
        }
        try {
            return hexStringToByteArray(digest);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse vbmeta.digest", e);
            return null;
        }
    }

    public static int getOsVersion() {
        switch (Build.VERSION.SDK_INT) {
            case Build.VERSION_CODES.Q: return 100000;
            case Build.VERSION_CODES.R: return 110000;
            case Build.VERSION_CODES.S: return 120000;
            case Build.VERSION_CODES.S_V2: return 120100;
            case Build.VERSION_CODES.TIRAMISU: return 130000;
            case Build.VERSION_CODES.UPSIDE_DOWN_CAKE: return 140000;
            case Build.VERSION_CODES.VANILLA_ICE_CREAM: return 150000;
            default: return (Build.VERSION.SDK_INT - 20) * 10000;
        }
    }

    public static int getAttestVersion() {
        switch (Build.VERSION.SDK_INT) {
            case Build.VERSION_CODES.Q:
            case Build.VERSION_CODES.R:
                return 4;
            case Build.VERSION_CODES.S:
            case Build.VERSION_CODES.S_V2:
                return 100;
            case Build.VERSION_CODES.TIRAMISU:
                return 200;
            case Build.VERSION_CODES.UPSIDE_DOWN_CAKE:
            case Build.VERSION_CODES.VANILLA_ICE_CREAM:
                return 300;
            default:
                return 400;
        }
    }

    public static int getKeymasterVersion() {
        int attestVersion = getAttestVersion();
        return attestVersion == 4 ? 41 : attestVersion;
    }

    public static int getPatchLevel(boolean isLong) {
        return getPatchLevel(isLong, null);
    }

    public static int getPatchLevel(boolean isLong, String[] packages) {
        TrickyStoreService.CustomPatchLevel customLevel =
            TrickyStoreService.getInstance().getCustomPatchLevelForPackage(packages);
        if (customLevel != null && customLevel.system != null) {
            Integer parsed = parsePatchLevel(customLevel.system, isLong);
            if (parsed != null) return parsed;
        }
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, isLong);
    }

    public static int getVendorPatchLevel(boolean isLong) {
        return getVendorPatchLevel(isLong, null);
    }

    public static int getVendorPatchLevel(boolean isLong, String[] packages) {
        TrickyStoreService.CustomPatchLevel customLevel =
            TrickyStoreService.getInstance().getCustomPatchLevelForPackage(packages);
        if (customLevel != null && customLevel.vendor != null) {
            Integer parsed = parsePatchLevel(customLevel.vendor, isLong);
            if (parsed != null) return parsed;
        }
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, isLong);
    }

    public static int getBootPatchLevel(boolean isLong) {
        return getBootPatchLevel(isLong, null);
    }

    public static int getBootPatchLevel(boolean isLong, String[] packages) {
        TrickyStoreService.CustomPatchLevel customLevel =
            TrickyStoreService.getInstance().getCustomPatchLevelForPackage(packages);
        if (customLevel != null && customLevel.boot != null) {
            Integer parsed = parsePatchLevel(customLevel.boot, isLong);
            if (parsed != null) return parsed;
        }
        return convertPatchLevel(Build.VERSION.SECURITY_PATCH, isLong);
    }

    private static Integer parsePatchLevel(String value, boolean isLong) {
        if (value == null || value.equalsIgnoreCase("no") || value.equalsIgnoreCase("prop")) {
            return null;
        }
        String normalized = value.replace("-", "");
        if (!normalized.matches("[0-9]{6}([0-9]{2})?")) {
            return null;
        }
        try {
            int year = Integer.parseInt(normalized.substring(0, 4));
            int month = Integer.parseInt(normalized.substring(4, 6));
            int day = normalized.length() == 8
                    ? Integer.parseInt(normalized.substring(6, 8)) : 1;
            if (year < 1) {
                return null;
            }
            java.time.LocalDate.of(year, month, day);
            return isLong ? year * 10000 + month * 100 + day : year * 100 + month;
        } catch (java.time.DateTimeException | NumberFormatException e) {
            return null;
        }
    }

    public static int convertPatchLevel(String patchString, boolean isLong) {
        Integer parsed = parsePatchLevel(patchString, isLong);
        if (parsed != null) {
            return parsed;
        }
        Log.w(TAG, "Invalid patch level format; using fallback");
        return isLong ? 20240401 : 202404;
    }

    public static byte[] computeModuleHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(new byte[0]);
        } catch (Exception e) {
            Log.e(TAG, "Failed to compute module hash", e);
            return new byte[32];
        }
    }

    private static byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

    private static byte[] hexStringToByteArray(String hex) {
        int len = hex.length();
        if ((len & 1) != 0) {
            throw new IllegalArgumentException("Odd hexadecimal digest length");
        }
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("Invalid hexadecimal digest");
            }
            data[i / 2] = (byte) ((high << 4) + low);
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
