/**
 * Copyright [2018] [Jonathan S. Fisher]
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package com.github.exabrial.speakeasy.symmetric.hmacsha2;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.primitives.FingerPrinter;
import com.github.exabrial.speakeasy.primitives.Signer;
import com.github.exabrial.speakeasy.primitives.Verifier;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.HMACSHA256_SIG_LENGTH;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.HMAC_SHA256;

public class HMACSHA256SignerVerifier implements Signer, Verifier, FingerPrinter {
  private final SymmetricKey symmetricKey;
  private final StringEncoder stringEncoder;

  public HMACSHA256SignerVerifier(final SymmetricKey symmetricKey) {
    this.symmetricKey = symmetricKey;
    this.stringEncoder = Base64StringEncoder.getSingleton();
  }

  public HMACSHA256SignerVerifier(final SymmetricKey symmetricKey, final StringEncoder stringEncoder) {
    this.symmetricKey = symmetricKey;
    this.stringEncoder = stringEncoder;
  }

  @Override
  public String signMessage(final String message) {
    try {
      final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
      final Mac hmac = Mac.getInstance(HMAC_SHA256);
      final SecretKeySpec secret_key = new SecretKeySpec(symmetricKey.getKeyBytes(), HMAC_SHA256);
      hmac.init(secret_key);
      final byte[] signatureBytes = hmac.doFinal(messageBytes);
      final String signature = stringEncoder.encodeBytesAsString(signatureBytes);
      return signature;
    } catch (InvalidKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean verifyMessageSignature(final String message, final String signature) {
    try {
      final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
      final Mac hmac = Mac.getInstance(HMAC_SHA256);
      final SecretKeySpec secret_key = new SecretKeySpec(symmetricKey.getKeyBytes(), HMAC_SHA256);
      hmac.init(secret_key);
      final byte[] cSignatureBytes = hmac.doFinal(messageBytes);
      final byte[] pSignatureBytes = getBytes(signature, cSignatureBytes.length);
      return compare(cSignatureBytes, pSignatureBytes);
    } catch (final InvalidKeyException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public String fingerPrint(final String message) {
    return signMessage(message);
  }

  @Override
  public boolean compare(final String calculatedFingerPrint, final String presentedFingerPrint) {
    final byte[] cSignatureBytes = getBytes(calculatedFingerPrint, HMACSHA256_SIG_LENGTH);
    final byte[] pSignatureBytes = getBytes(presentedFingerPrint, HMACSHA256_SIG_LENGTH);
    return compare(cSignatureBytes, pSignatureBytes);
  }

  private byte[] getBytes(final String signature, final int length) {
    byte[] pSignatureBytes;
    try {
      pSignatureBytes = stringEncoder.decodeStringToBytes(signature);
    } catch (final IllegalArgumentException e) {
      pSignatureBytes = new byte[length];
    }
    return pSignatureBytes;
  }

  private boolean compare(final byte[] cSignatureBytes, final byte[] pSignatureBytes) {
    boolean isValid = true;
    // Arrays.equals would be great
    // MAC comparisons should be constant time however
    for (int i = 0; i < cSignatureBytes.length; i++) {
      final byte cByte = cSignatureBytes[i];
      if (i < pSignatureBytes.length) {
        final byte pByte = pSignatureBytes[i];
        if (isValid) {
          isValid = cByte == pByte;
        }
      } else {
        isValid = false;
      }
    }
    return isValid;
  }
}
