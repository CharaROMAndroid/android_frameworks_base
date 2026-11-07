package android.security.trickystore;

import android.app.ActivityThread;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import com.android.internal.org.bouncycastle.asn1.ASN1Boolean;
import com.android.internal.org.bouncycastle.asn1.ASN1Encodable;
import com.android.internal.org.bouncycastle.asn1.ASN1EncodableVector;
import com.android.internal.org.bouncycastle.asn1.ASN1Enumerated;
import com.android.internal.org.bouncycastle.asn1.ASN1Integer;
import com.android.internal.org.bouncycastle.asn1.ASN1ObjectIdentifier;
import com.android.internal.org.bouncycastle.asn1.ASN1OctetString;
import com.android.internal.org.bouncycastle.asn1.DEROctetString;
import com.android.internal.org.bouncycastle.asn1.DERSequence;
import com.android.internal.org.bouncycastle.asn1.DERSet;
import com.android.internal.org.bouncycastle.asn1.DERTaggedObject;
import com.android.internal.org.bouncycastle.asn1.DERNull;
import com.android.internal.org.bouncycastle.asn1.x500.X500Name;
import com.android.internal.org.bouncycastle.asn1.x509.Extension;
import com.android.internal.org.bouncycastle.asn1.x509.KeyUsage;
import com.android.internal.org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import com.android.internal.org.bouncycastle.cert.X509CertificateHolder;
import com.android.internal.org.bouncycastle.cert.X509v3CertificateBuilder;
import com.android.internal.org.bouncycastle.operator.ContentSigner;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

/**
 * @hide
 */
public final class CertificateGenerator {
    private static final String TAG = "CertificateGenerator";
    private static final int MAX_ATTESTATION_CHALLENGE_SIZE = 128;

    public static final ASN1ObjectIdentifier ATTESTATION_OID =
        new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");

    private CertificateGenerator() {}

    /** @hide */
    public static class KeyGenParameters {
        public int keySize;
        public int algorithm;
        public BigInteger certificateSerial;
        public Date certificateNotBefore;
        public Date certificateNotAfter;
        public X500Principal certificateSubject;
        public BigInteger rsaPublicExponent;
        public int ecCurve;
        public String ecCurveName;
        public List<Integer> purpose = new ArrayList<>();
        public List<Integer> digest = new ArrayList<>();
        public List<Integer> rsaOaepMgfDigest = new ArrayList<>();
        public List<Integer> padding = new ArrayList<>();
        public String[] packages;
        public byte[] attestationChallenge;
        public byte[] brand;
        public byte[] device;
        public byte[] product;
        public byte[] manufacturer;
        public byte[] model;

        public String getEcCurveName() {
            if (ecCurveName != null) return ecCurveName;
            switch (keySize) {
                case 224: return "secp224r1";
                case 256: return "secp256r1";
                case 384: return "secp384r1";
                case 521: return "secp521r1";
                default: return "secp256r1";
            }
        }
    }

    public static KeyPair generateKeyPair(KeyGenParameters params) {
        try {
            KeyPairGenerator kpg;
            if (params.algorithm == 3) {
                kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(params.getEcCurveName()));
            } else if (params.algorithm == 1) {
                kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(new RSAKeyGenParameterSpec(
                    params.keySize,
                    params.rsaPublicExponent != null ? params.rsaPublicExponent : RSAKeyGenParameterSpec.F4
                ));
            } else {
                Log.e(TAG, "Unsupported algorithm: " + params.algorithm);
                return null;
            }
            return kpg.generateKeyPair();
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate key pair", e);
            return null;
        }
    }

    public static List<Certificate> generateCertificateChain(
            KeyPair keyPair,
            KeyGenParameters params,
            int securityLevel,
            int uid) {
        return TrickyStoreService.getInstance().requestCertificateChain(
                keyPair.getPublic(), params, securityLevel);
    }
}
