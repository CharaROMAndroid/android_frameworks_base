/* Moved unchanged in structure from core CertificateHacker; signing stays in services.jar. */
package com.android.server.spoof;
import android.security.trickystore.*;

import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1Sequence;
import com.android.internal.org.bouncycastle.asn1.ASN1TaggedObject;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;
import com.android.internal.org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import com.android.internal.org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @hide
 */
final class TrickyStoreCertificateHacker {
    private static final String TAG = "CertificateHacker";

    private static final Map<String, String> sLeafAlgorithms = new ConcurrentHashMap<>();

    private TrickyStoreCertificateHacker() {}

    public static void clearLeafAlgorithms() {
        sLeafAlgorithms.clear();
    }

    public static Certificate[] hackCertificateChain(Certificate[] chain) {
        return hackCertificateChain(chain, null);
    }

    public static Certificate[] hackCertificateChain(Certificate[] chain, String[] packages) {
        if (chain == null || chain.length == 0) {
            return chain;
        }

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate leaf = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(chain[0].getEncoded()));

            byte[] extensionBytes = leaf.getExtensionValue(
                CertificateGenerator.ATTESTATION_OID.getId());
            if (extensionBytes == null) {
                return chain;
            }

            X509CertificateHolder leafHolder = new X509CertificateHolder(leaf.getEncoded());
            Extension extension = leafHolder.getExtension(CertificateGenerator.ATTESTATION_OID);
            ASN1Sequence sequence = ASN1Sequence.getInstance(extension.getExtnValue().getOctets());
            ASN1Encodable[] encodables = sequence.toArray();
            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            // Attestation-ID (hardware identity) overrides. Empty here: the leaf's
            // real BRAND/DEVICE/PRODUCT/MANUFACTURER/MODEL tags pass through untouched.
            // If a Build-spoof subsystem is added later, populate this map (tag -> UTF-8
            // bytes) and the drop/re-add logic below keeps the certified identity and the
            // GMS-visible Build fields in agreement.
            Map<Integer, byte[]> attestationIdOverrides = getAttestationIdOverrides();

            ASN1EncodableVector vector = new ASN1EncodableVector();
            ASN1Encodable originalRootOfTrust = null;

            for (ASN1Encodable element : teeEnforced) {
                ASN1TaggedObject taggedObject = (ASN1TaggedObject) element;
                int tagNo = taggedObject.getTagNo();
                if (tagNo == 704) {
                    originalRootOfTrust = taggedObject.getBaseObject().toASN1Primitive();
                } else if (tagNo == 705 || tagNo == 706 || tagNo == 718 || tagNo == 719) {
                    // Real KeyMint already reports these; hackAttestExtension() re-adds
                    // them with the configured values, so keeping the originals would
                    // emit each tag twice.
                } else if (attestationIdOverrides.containsKey(tagNo)) {
                    // Dropped here; the spoofed replacement is added back in
                    // hackAttestExtension() so the certified identity and the
                    // GMS-visible Build fields can't disagree.
                } else {
                    vector.add(taggedObject);
                }
            }

            String algorithm = leaf.getPublicKey().getAlgorithm();
            KeyBoxManager keyboxManager = TrickyStoreService.getInstance().getKeyBoxManager();
            KeyBoxManager.KeyBox keybox = keyboxManager.getKeybox(algorithm);

            if (keybox == null) {
                return chain;
            }

            List<Certificate> certificates = new ArrayList<>(keybox.certificates);
            X509CertificateHolder issuerHolder = new X509CertificateHolder(
                certificates.get(0).getEncoded());

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                issuerHolder.getSubject(),
                leafHolder.getSerialNumber(),
                leafHolder.getNotBefore(),
                leafHolder.getNotAfter(),
                leafHolder.getSubject(),
                leafHolder.getSubjectPublicKeyInfo()
            );

            ContentSigner signer = createBCSigner(leaf.getSigAlgName(), keybox.keyPair.getPrivate());

            Extension hackedExtension = hackAttestExtension(
                originalRootOfTrust, vector, encodables, attestationIdOverrides, packages);

            // Keep the leaf's original extension order (KeyUsage, then attestation)
            // instead of moving the attestation extension to the front.
            for (Object oid : leafHolder.getExtensions().getExtensionOIDs()) {
                String oidString = oid.toString();
                if (oidString.equals(CertificateGenerator.ATTESTATION_OID.getId())) {
                    builder.addExtension(hackedExtension);
                } else {
                    builder.addExtension(leafHolder.getExtension(
                        new ASN1ObjectIdentifier(oidString)));
                }
            }

            X509CertificateHolder builtHolder = builder.build(signer);
            X509Certificate hackedLeaf = (X509Certificate) certFactory.generateCertificate(
                new ByteArrayInputStream(builtHolder.getEncoded()));

            List<Certificate> result = new ArrayList<>();
            result.add(hackedLeaf);
            result.addAll(certificates);
            return result.toArray(new Certificate[0]);
        } catch (Exception e) {
            // Fail closed without logging certificate material.
            return chain;
        }
    }

    // The subject key and the original issuer can use different algorithms from
    // the replacement issuer. Derive the signing primitive from the actual key.
    static ContentSigner createBCSigner(String originalAlgorithm, PrivateKey privateKey)
            throws Exception {
        String digest = "SHA256";
        String original = originalAlgorithm.toUpperCase(java.util.Locale.ROOT)
                .replace("-", "");
        if (original.startsWith("SHA384")) digest = "SHA384";
        else if (original.startsWith("SHA512")) digest = "SHA512";
        String keyAlgorithm = privateKey.getAlgorithm();
        String algorithm;
        if ("EC".equalsIgnoreCase(keyAlgorithm)) {
            algorithm = digest + "withECDSA";
        } else if ("RSA".equalsIgnoreCase(keyAlgorithm)) {
            algorithm = digest + "withRSA";
        } else {
            throw new IllegalArgumentException("Unsupported issuer key algorithm: " + keyAlgorithm);
        }
        return new JcaContentSignerBuilder(algorithm)
                .setProvider(new BouncyCastleProvider()).build(privateKey);
    }

    /**
     * Hardware-identity (attestation-ID) overrides, keyed by KeyMint tag number
     * (710 BRAND, 711 DEVICE, 712 PRODUCT, 716 MANUFACTURER, 717 MODEL).
     *
     * This build has no Build-spoof subsystem, so the map is empty and the leaf's
     * real identity tags pass through unchanged. To integrate one later, return a
     * populated map here (tag -> UTF-8 bytes); hackCertificateChain() already drops
     * the originals for any tag present in this map and hackAttestExtension() re-adds
     * the override, so the attestation cert and the GMS-visible Build fields stay
     * consistent with no other changes.
     */
    private static Map<Integer, byte[]> getAttestationIdOverrides() {
        return Collections.emptyMap();
    }

    private static Extension hackAttestExtension(
            ASN1Encodable originalRootOfTrust,
            ASN1EncodableVector vector,
            ASN1Encodable[] originalEncodables,
            Map<Integer, byte[]> attestationIdOverrides,
            String[] packages) throws Exception {

        byte[] bootKey = TrickyStoreSigner.bootDigest(false);
        byte[] bootHash = TrickyStoreSigner.bootDigest(true);

        if (bootHash == null && originalRootOfTrust instanceof ASN1Sequence) {
            try {
                ASN1Sequence rot = (ASN1Sequence) originalRootOfTrust;
                ASN1Encodable hashElement = rot.getObjectAt(3);
                if (hashElement instanceof DEROctetString) {
                    bootHash = ((DEROctetString) hashElement).getOctets();
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to extract boot hash from original", e);
            }
        }

        if (bootHash == null) {
            bootHash = TrickyStoreSigner.bootDigest(true);
        }

        ASN1Encodable[] rootOfTrustElements = new ASN1Encodable[] {
            new DEROctetString(bootKey),
            ASN1Boolean.TRUE,
            new ASN1Enumerated(0),
            new DEROctetString(bootHash)
        };
        DERSequence hackedRootOfTrust = new DERSequence(rootOfTrustElements);

        // Collect everything by tag so the list is emitted in ascending tag order,
        // like real KeyMint output.
        java.util.TreeMap<Integer, ASN1Encodable> ordered = new java.util.TreeMap<>();
        for (int i = 0; i < vector.size(); i++) {
            ASN1TaggedObject t = (ASN1TaggedObject) vector.get(i);
            ordered.put(t.getTagNo(), t);
        }
        ordered.put(718, new DERTaggedObject(true, 718,
            new ASN1Integer(AttestationUtils.getVendorPatchLevel(true, packages))));
        ordered.put(719, new DERTaggedObject(true, 719,
            new ASN1Integer(AttestationUtils.getBootPatchLevel(true, packages))));
        ordered.put(706, new DERTaggedObject(true, 706,
            new ASN1Integer(AttestationUtils.getPatchLevel(false, packages))));
        ordered.put(705, new DERTaggedObject(true, 705,
            new ASN1Integer(AttestationUtils.getOsVersion())));
        ordered.put(704, new DERTaggedObject(704, hackedRootOfTrust));

        // Re-add any hardware identity tags dropped in hackCertificateChain().
        // Empty in this build (see getAttestationIdOverrides()).
        for (Map.Entry<Integer, byte[]> entry : attestationIdOverrides.entrySet()) {
            ordered.put(entry.getKey(), new DERTaggedObject(true, entry.getKey(),
                new DEROctetString(entry.getValue())));
        }

        ASN1EncodableVector orderedVector = new ASN1EncodableVector();
        for (ASN1Encodable e : ordered.values()) {
            orderedVector.add(e);
        }

        DERSequence hackedEnforced = new DERSequence(orderedVector);
        originalEncodables[7] = hackedEnforced;
        DERSequence hackedSequence = new DERSequence(originalEncodables);
        DEROctetString hackedOctets = new DEROctetString(hackedSequence);

        return new Extension(CertificateGenerator.ATTESTATION_OID, false, hackedOctets);
    }

    public static void storeLeafAlgorithm(String alias, int uid, String algorithm) {
        sLeafAlgorithms.put(alias + "_" + uid, algorithm);
    }

    public static String getLeafAlgorithm(String alias, int uid) {
        return sLeafAlgorithms.remove(alias + "_" + uid);
    }
}
