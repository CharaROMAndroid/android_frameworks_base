/*
 * Copyright (C) 2025-2026 CharaROM
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
 *
 * Based on TrickyStoreOSS SoftwareOperationBinder.kt
 * Original copyright: Copyright 2026 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.security.trickystore;

import android.hardware.security.keymint.Algorithm;
import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyParameterValue;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.Tag;
import android.os.RemoteException;
import android.os.ServiceSpecificException;
import android.security.keymaster.KeymasterDefs;
import android.system.keystore2.IKeystoreOperation;
import android.system.keystore2.ResponseCode;
import android.util.Log;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Software-backed IKeystoreOperation implementation.
 * Handles cryptographic operations entirely in software without touching the TEE.
 * 
 * Based on TrickyStoreOSS SoftwareOperationBinder.kt by Dakkshesh.
 * @hide
 */
public class SoftwareOperationBinder extends IKeystoreOperation.Stub {
    private static final String TAG = "SoftwareOperationBinder";
    private static final int MAX_RECEIVE_DATA = 0x8000;
    
    private final OpEngine mEngine;
    private final TrickyStoreService.SoftwareKeyEntry mKeyEntry;
    private volatile boolean mActive = true;
    private KeyParameter[] mBeginParameters;
    
    private SoftwareOperationBinder(OpEngine engine, TrickyStoreService.SoftwareKeyEntry keyEntry,
            KeyParameter[] beginParameters) {
        this.mEngine = engine;
        this.mKeyEntry = keyEntry;
        this.mBeginParameters = beginParameters;
    }
    
    public KeyParameter[] getBeginParameters() {
        return mBeginParameters;
    }
    
    @Override
    public synchronized byte[] update(byte[] input) throws RemoteException {
        checkActive();
        checkInput(input);
        return mEngine.update(input);
    }
    
    @Override
    public synchronized void updateAad(byte[] aadInput) throws RemoteException {
        checkActive();
        checkInput(aadInput);
        try {
            mEngine.updateAad(aadInput);
        } catch (Throwable e) {
            mActive = false;
            throw e;
        }
    }
    
    @Override
    public synchronized byte[] finish(byte[] input, byte[] signature) throws RemoteException {
        checkActive();
        checkInput(input);
        if (mKeyEntry != null && !mKeyEntry.consumeUsage()) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_EXPIRED,
                    "Key usage limit expired");
        }
        try {
            return mEngine.finish(input, signature);
        } catch (ServiceSpecificException e) {
            throw e;
        } catch (AEADBadTagException e) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                    "GCM tag verification failed");
        } catch (Throwable e) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                    e.getMessage() != null ? e.getMessage() : "operation failed");
        } finally {
            mActive = false;
        }
    }
    
    @Override
    public synchronized void abort() throws RemoteException {
        mActive = false;
    }
    
    private void checkActive() {
        if (!mActive) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_OPERATION_HANDLE,
                    "Operation is no longer active");
        }
    }
    
    private void checkInput(byte[] data) {
        if (data != null && data.length > MAX_RECEIVE_DATA) {
            throw new ServiceSpecificException(ResponseCode.TOO_MUCH_DATA,
                    "Oversized input (" + data.length + "B)");
        }
    }
    
    // Operation engine interface
    private interface OpEngine {
        byte[] update(byte[] data) throws RemoteException;
        void updateAad(byte[] data) throws RemoteException;
        byte[] finish(byte[] data, byte[] signature) throws RemoteException;
    }
    
    // Signature engine
    private static class SignatureEngine implements OpEngine {
        private final Signature mSignature;
        private final boolean mVerify;
        
        SignatureEngine(Signature signature, boolean verify) {
            this.mSignature = signature;
            this.mVerify = verify;
        }
        
        @Override
        public byte[] update(byte[] data) throws RemoteException {
            try {
                if (data != null) mSignature.update(data);
            } catch (Exception e) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR, 
                        e.getMessage());
            }
            return null;
        }
        
        @Override
        public void updateAad(byte[] data) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_TAG,
                    "updateAad not supported");
        }
        
        @Override
        public byte[] finish(byte[] data, byte[] signature) throws RemoteException {
            try {
                if (data != null) mSignature.update(data);
                if (mVerify) {
                    if (signature == null || !mSignature.verify(signature)) {
                        throw new ServiceSpecificException(
                                KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                                "Signature verification failed");
                    }
                    return null;
                } else {
                    return mSignature.sign();
                }
            } catch (ServiceSpecificException e) {
                throw e;
            } catch (Exception e) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR,
                        e.getMessage());
            }
        }
    }
    
    // MAC engine
    private static class MacEngine implements OpEngine {
        private final Mac mMac;
        private final boolean mVerify;
        
        MacEngine(Mac mac, boolean verify) {
            this.mMac = mac;
            this.mVerify = verify;
        }
        
        @Override
        public byte[] update(byte[] data) {
            if (data != null) mMac.update(data);
            return null;
        }
        
        @Override
        public void updateAad(byte[] data) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_TAG,
                    "updateAad not supported");
        }
        
        @Override
        public byte[] finish(byte[] data, byte[] signature) {
            if (data != null) mMac.update(data);
            byte[] tag = mMac.doFinal();
            if (mVerify) {
                if (signature == null || !MessageDigest.isEqual(tag, signature)) {
                    throw new ServiceSpecificException(
                            KeymasterDefs.KM_ERROR_VERIFICATION_FAILED,
                            "HMAC verification failed");
                }
                return null;
            }
            return tag;
        }
    }
    
    // Cipher engine
    private static class CipherEngine implements OpEngine {
        private final Cipher mCipher;
        
        CipherEngine(Cipher cipher) {
            this.mCipher = cipher;
        }
        
        byte[] getIv() {
            return mCipher.getIV();
        }
        
        @Override
        public byte[] update(byte[] data) {
            return data != null ? mCipher.update(data) : null;
        }
        
        @Override
        public void updateAad(byte[] data) {
            if (data != null) mCipher.updateAAD(data);
        }
        
        @Override
        public byte[] finish(byte[] data, byte[] signature) throws RemoteException {
            try {
                return data != null ? mCipher.doFinal(data) : mCipher.doFinal();
            } catch (Exception e) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR,
                        e.getMessage());
            }
        }
    }
    
    // Key agreement engine
    private static class KeyAgreementEngine implements OpEngine {
        private final KeyAgreement mAgreement;
        
        KeyAgreementEngine(KeyAgreement agreement) {
            this.mAgreement = agreement;
        }
        
        @Override
        public byte[] update(byte[] data) {
            return null;
        }
        
        @Override
        public void updateAad(byte[] data) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_INVALID_TAG,
                    "updateAad not supported");
        }
        
        @Override
        public byte[] finish(byte[] data, byte[] signature) throws RemoteException {
            try {
                if (data != null) {
                    PublicKey peerKey = KeyFactory.getInstance("EC")
                            .generatePublic(new X509EncodedKeySpec(data));
                    mAgreement.doPhase(peerKey, true);
                }
                return mAgreement.generateSecret();
            } catch (Exception e) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR,
                        e.getMessage());
            }
        }
    }
    
    /**
     * Create a software operation binder for the given key and operation parameters.
     */
    public static SoftwareOperationBinder create(
            TrickyStoreService.SoftwareKeyEntry keyEntry,
            int purpose,
            int digest,
            int padding,
            int blockMode,
            byte[] nonce,
            Integer macLength,
            int mgfDigest) throws ServiceSpecificException {
        
        int algorithm = keyEntry.algorithm;
        KeyPair kp = keyEntry.keyPair;
        
        // Validate purpose
        boolean purposeAllowed = false;
        for (int p : keyEntry.purposes) {
            if (p == purpose) {
                purposeAllowed = true;
                break;
            }
        }
        if (!purposeAllowed) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_INCOMPATIBLE_PURPOSE,
                    "Purpose " + purpose + " not allowed for this key");
        }
        
        // Check time validity
        long now = System.currentTimeMillis();
        if (keyEntry.validityStart != null && now < keyEntry.validityStart) {
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_NOT_YET_VALID,
                    "Key not yet valid");
        }
        if (purpose == KeyPurpose.SIGN || purpose == KeyPurpose.ENCRYPT) {
            if (keyEntry.validityEndOrigination != null && now > keyEntry.validityEndOrigination) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_EXPIRED,
                        "Key expired for origination");
            }
        }
        if (purpose == KeyPurpose.DECRYPT || purpose == KeyPurpose.VERIFY) {
            if (keyEntry.validityEndConsumption != null && now > keyEntry.validityEndConsumption) {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_KEY_EXPIRED,
                        "Key expired for consumption");
            }
        }
        
        // Pick defaults if not specified
        if (digest == 0 && keyEntry.digests.length > 0) {
            digest = keyEntry.digests[0];
        }
        if (digest == 0) {
            digest = KeymasterDefs.KM_DIGEST_SHA_2_256;
        }
        
        if (padding == 0 && keyEntry.paddings.length > 0) {
            padding = keyEntry.paddings[0];
        }
        
        if (blockMode == 0 && keyEntry.blockModes.length > 0) {
            blockMode = keyEntry.blockModes[0];
        }
        
        if (mgfDigest == 0 && keyEntry.mgf1Digests.length > 0) {
            mgfDigest = keyEntry.mgf1Digests[0];
        }
        if (mgfDigest == 0) {
            mgfDigest = KeymasterDefs.KM_DIGEST_SHA1;
        }
        
        OpEngine engine;
        KeyParameter[] beginParams = null;
        
        try {
            if (algorithm == KeymasterDefs.KM_ALGORITHM_EC ||
                algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
                switch (purpose) {
                    case KeyPurpose.SIGN: {
                        String sigAlgo = getSignatureAlgorithm(algorithm, digest, padding);
                        Signature sig = Signature.getInstance(sigAlgo);
                        sig.initSign(kp.getPrivate());
                        engine = new SignatureEngine(sig, false);
                        break;
                    }
                    case KeyPurpose.VERIFY: {
                        String sigAlgo = getSignatureAlgorithm(algorithm, digest, padding);
                        Signature sig = Signature.getInstance(sigAlgo);
                        sig.initVerify(kp.getPublic());
                        engine = new SignatureEngine(sig, true);
                        break;
                    }
                    case KeyPurpose.AGREE_KEY: {
                        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                        ka.init(kp.getPrivate());
                        engine = new KeyAgreementEngine(ka);
                        break;
                    }
                    case KeyPurpose.ENCRYPT:
                    case KeyPurpose.DECRYPT: {
                        Cipher cipher = buildCipher(algorithm, digest, padding, blockMode, 
                                nonce, macLength, mgfDigest, kp, null, purpose);
                        CipherEngine ce = new CipherEngine(cipher);
                        byte[] iv = ce.getIv();
                        if (iv != null) {
                            beginParams = new KeyParameter[1];
                            beginParams[0] = new KeyParameter();
                            beginParams[0].tag = Tag.NONCE;
                            beginParams[0].value = KeyParameterValue.blob(iv);
                        }
                        engine = ce;
                        break;
                    }
                    default:
                        throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                                "Unsupported purpose: " + purpose);
                }
            } else if (algorithm == KeymasterDefs.KM_ALGORITHM_AES) {
                if (purpose != KeyPurpose.ENCRYPT && purpose != KeyPurpose.DECRYPT) {
                    throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_PURPOSE,
                            "Unsupported purpose for AES: " + purpose);
                }
                // AES not supported for asymmetric-only software keys
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        "AES not supported in software attestation keys");
            } else if (algorithm == KeymasterDefs.KM_ALGORITHM_HMAC) {
                // HMAC not supported for asymmetric-only software keys
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        "HMAC not supported in software attestation keys");
            } else {
                throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNSUPPORTED_ALGORITHM,
                        "Unsupported algorithm: " + algorithm);
            }
        } catch (ServiceSpecificException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Failed to create operation", e);
            throw new ServiceSpecificException(KeymasterDefs.KM_ERROR_UNKNOWN_ERROR,
                    e.getMessage());
        }
        
        return new SoftwareOperationBinder(engine, keyEntry, beginParams);
    }
    
    private static String getSignatureAlgorithm(int algorithm, int digest, int padding) {
        String digestName = getDigestName(digest);
        if (algorithm == KeymasterDefs.KM_ALGORITHM_EC) {
            return digestName + "withECDSA";
        } else {
            if (padding == KeymasterDefs.KM_PAD_RSA_PSS) {
                return digestName + "withRSA/PSS";
            }
            return digestName + "withRSA";
        }
    }
    
    private static String getDigestName(int digest) {
        switch (digest) {
            case KeymasterDefs.KM_DIGEST_SHA1:
                return "SHA1";
            case KeymasterDefs.KM_DIGEST_SHA_2_224:
                return "SHA224";
            case KeymasterDefs.KM_DIGEST_SHA_2_256:
                return "SHA256";
            case KeymasterDefs.KM_DIGEST_SHA_2_384:
                return "SHA384";
            case KeymasterDefs.KM_DIGEST_SHA_2_512:
                return "SHA512";
            case KeymasterDefs.KM_DIGEST_MD5:
                return "MD5";
            default:
                return "SHA256";
        }
    }
    
    private static MGF1ParameterSpec getMgf1Spec(int digest) {
        switch (digest) {
            case KeymasterDefs.KM_DIGEST_SHA1:
                return MGF1ParameterSpec.SHA1;
            case KeymasterDefs.KM_DIGEST_SHA_2_224:
                return MGF1ParameterSpec.SHA224;
            case KeymasterDefs.KM_DIGEST_SHA_2_256:
                return MGF1ParameterSpec.SHA256;
            case KeymasterDefs.KM_DIGEST_SHA_2_384:
                return MGF1ParameterSpec.SHA384;
            case KeymasterDefs.KM_DIGEST_SHA_2_512:
                return MGF1ParameterSpec.SHA512;
            default:
                return MGF1ParameterSpec.SHA1;
        }
    }
    
    private static Cipher buildCipher(int algorithm, int digest, int padding, int blockMode,
            byte[] nonce, Integer macLength, int mgfDigest,
            KeyPair kp, javax.crypto.SecretKey secretKey, int purpose) throws Exception {
        
        String keyAlgo;
        if (algorithm == KeymasterDefs.KM_ALGORITHM_RSA) {
            keyAlgo = "RSA";
        } else if (algorithm == KeymasterDefs.KM_ALGORITHM_AES) {
            keyAlgo = "AES";
        } else {
            throw new IllegalArgumentException("Unsupported cipher algorithm: " + algorithm);
        }
        
        String mode;
        switch (blockMode) {
            case KeymasterDefs.KM_MODE_ECB:
                mode = "ECB";
                break;
            case KeymasterDefs.KM_MODE_CBC:
                mode = "CBC";
                break;
            case KeymasterDefs.KM_MODE_CTR:
                mode = "CTR";
                break;
            case KeymasterDefs.KM_MODE_GCM:
                mode = "GCM";
                break;
            default:
                mode = "ECB";
        }
        
        String pad;
        switch (padding) {
            case KeymasterDefs.KM_PAD_NONE:
                pad = "NoPadding";
                break;
            case KeymasterDefs.KM_PAD_RSA_OAEP:
                pad = "OAEPPadding";
                break;
            case KeymasterDefs.KM_PAD_RSA_PKCS1_1_5_ENCRYPT:
            case KeymasterDefs.KM_PAD_RSA_PKCS1_1_5_SIGN:
                pad = "PKCS1Padding";
                break;
            case KeymasterDefs.KM_PAD_PKCS7:
                pad = "PKCS7Padding";
                break;
            default:
                pad = "NoPadding";
        }
        
        int opMode = purpose == KeyPurpose.ENCRYPT ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
        
        Cipher cipher = Cipher.getInstance(keyAlgo + "/" + mode + "/" + pad);
        
        java.security.spec.AlgorithmParameterSpec spec = null;
        if (blockMode == KeymasterDefs.KM_MODE_GCM) {
            int tagLen = macLength != null ? macLength : 128;
            byte[] iv = nonce != null ? nonce : new byte[12];
            spec = new GCMParameterSpec(tagLen, iv);
        } else if (padding == KeymasterDefs.KM_PAD_RSA_OAEP) {
            spec = new OAEPParameterSpec(
                    getDigestNameForOAEP(digest),
                    "MGF1",
                    getMgf1Spec(mgfDigest),
                    PSource.PSpecified.DEFAULT);
        } else if (nonce != null) {
            spec = new IvParameterSpec(nonce);
        }
        
        java.security.Key key;
        if (secretKey != null) {
            key = secretKey;
        } else if (opMode == Cipher.ENCRYPT_MODE) {
            key = kp.getPublic();
        } else {
            key = kp.getPrivate();
        }
        
        if (spec != null) {
            cipher.init(opMode, key, spec);
        } else {
            cipher.init(opMode, key);
        }
        
        return cipher;
    }
    
    private static String getDigestNameForOAEP(int digest) {
        switch (digest) {
            case KeymasterDefs.KM_DIGEST_SHA1:
                return "SHA-1";
            case KeymasterDefs.KM_DIGEST_SHA_2_224:
                return "SHA-224";
            case KeymasterDefs.KM_DIGEST_SHA_2_256:
                return "SHA-256";
            case KeymasterDefs.KM_DIGEST_SHA_2_384:
                return "SHA-384";
            case KeymasterDefs.KM_DIGEST_SHA_2_512:
                return "SHA-512";
            default:
                return "SHA-256";
        }
    }
}
