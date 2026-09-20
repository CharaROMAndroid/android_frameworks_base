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
 */

package android.security.trickystore;

import android.hardware.security.keymint.KeyParameter;
import android.hardware.security.keymint.KeyPurpose;
import android.hardware.security.keymint.Tag;
import android.os.Binder;
import android.os.ServiceSpecificException;
import android.security.KeyStoreOperation;
import android.security.KeyStoreSecurityLevel;
import android.security.keymaster.KeymasterDefs;
import android.system.keystore2.CreateOperationResponse;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyMetadata;
import android.system.keystore2.KeyParameters;
import android.util.Log;

import java.util.Collection;

/**
 * Security level wrapper for software-backed keys.
 * Creates software operations via SoftwareOperationBinder instead of TEE operations.
 * 
 * Based on TrickyStoreOSS SecurityLevelInterceptor architecture.
 * @hide
 */
public class SoftwareKeyStoreSecurityLevel {
    private static final String TAG = "SoftwareKeyStoreSecurityLevel";
    
    private final int mSecurityLevel;
    private final KeyStoreSecurityLevel mRealSecurityLevel;
    
    /**
     * Create a software security level wrapper.
     * @param realSecurityLevel The real security level for fallback operations
     * @param securityLevel The reported security level value
     */
    public SoftwareKeyStoreSecurityLevel(KeyStoreSecurityLevel realSecurityLevel, int securityLevel) {
        this.mRealSecurityLevel = realSecurityLevel;
        this.mSecurityLevel = securityLevel;
    }
    
    /**
     * Create a software-backed operation for the given key.
     * 
     * @param uid The calling UID
     * @param alias The key alias
     * @param params Operation parameters
     * @return A KeyStoreOperation wrapping a SoftwareOperationBinder
     */
    public KeyStoreOperation createOperation(int uid, String alias, Collection<KeyParameter> params) 
            throws android.security.KeyStoreException {
        
        TrickyStoreService.SoftwareKeyEntry entry = 
                TrickyStoreService.getInstance().getSoftwareKey(uid, alias);
        
        if (entry == null) {
            throw new android.security.KeyStoreException(
                    android.system.keystore2.ResponseCode.KEY_NOT_FOUND,
                    "Software key not found: " + alias);
        }
        
        // Parse operation parameters
        int purpose = -1;
        int digest = 0;
        int padding = 0;
        int blockMode = 0;
        byte[] nonce = null;
        Integer macLength = null;
        int mgfDigest = 0;
        
        for (KeyParameter p : params) {
            try {
                switch (p.tag) {
                    case Tag.PURPOSE:
                        purpose = p.value.getKeyPurpose();
                        break;
                    case Tag.DIGEST:
                        digest = p.value.getDigest();
                        break;
                    case Tag.PADDING:
                        padding = p.value.getPaddingMode();
                        break;
                    case Tag.BLOCK_MODE:
                        blockMode = p.value.getBlockMode();
                        break;
                    case Tag.NONCE:
                        nonce = p.value.getBlob();
                        break;
                    case Tag.MAC_LENGTH:
                        macLength = p.value.getInteger();
                        break;
                    case Tag.RSA_OAEP_MGF_DIGEST:
                        mgfDigest = p.value.getDigest();
                        break;
                }
            } catch (Exception e) {
                // Ignore parsing errors for individual parameters
            }
        }
        
        if (purpose < 0) {
            throw new android.security.KeyStoreException(
                    KeymasterDefs.KM_ERROR_INVALID_ARGUMENT,
                    "No key purpose specified");
        }
        
        try {
            SoftwareOperationBinder op = SoftwareOperationBinder.create(
                    entry, purpose, digest, padding, blockMode, nonce, macLength, mgfDigest);
            
            Long challenge = null; // Software keys don't have hardware challenges
            KeyParameter[] returnParams = op.getBeginParameters();
            
            Log.d(TAG, "Created software operation for uid=" + uid + " alias=" + alias);
            
            return new KeyStoreOperation(op, challenge, returnParams);
        } catch (ServiceSpecificException e) {
            throw new android.security.KeyStoreException(e.errorCode, e.getMessage());
        }
    }
    
    /**
     * Create a software-backed operation using a key descriptor.
     */
    public KeyStoreOperation createOperation(KeyDescriptor descriptor, Collection<KeyParameter> params)
            throws android.security.KeyStoreException {
        int uid = Binder.getCallingUid();
        
        // Check if this is a software key
        String alias = descriptor.alias;
        if (alias == null) {
            // Try to resolve alias from nspace for grants
            TrickyStoreService.SoftwareKey key = 
                    TrickyStoreService.getInstance().getGrantOriginalKey(descriptor.nspace);
            if (key != null) {
                // This is a granted key - get the original entry
                TrickyStoreService.SoftwareKeyEntry entry =
                        TrickyStoreService.getInstance().getSoftwareKeyByGrant(descriptor.nspace, uid);
                if (entry != null) {
                    alias = key.alias;
                    uid = key.uid; // Use original owner's UID for key lookup
                }
            }
        }
        
        if (alias == null || !TrickyStoreService.getInstance().hasSoftwareKey(uid, alias)) {
            // Not a software key - fall through to real security level
            return mRealSecurityLevel.createOperation(descriptor, params);
        }
        
        return createOperation(uid, alias, params);
    }
    
    /**
     * Get the underlying real security level for operations on non-software keys.
     */
    public KeyStoreSecurityLevel getRealSecurityLevel() {
        return mRealSecurityLevel;
    }
    
    /**
     * Get the security level value.
     */
    public int getSecurityLevelValue() {
        return mSecurityLevel;
    }
}
