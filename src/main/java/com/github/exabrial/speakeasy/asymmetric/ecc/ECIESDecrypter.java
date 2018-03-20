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
package com.github.exabrial.speakeasy.asymmetric.ecc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;

import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.internal.GCMBufferedBlockCipher;
import com.github.exabrial.speakeasy.primitives.Decrypter;

import static com.github.exabrial.speakeasy.encoding.Base64StringEncoder.getSingleton;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.GCM_NONCE_LENGTH;

public class ECIESDecrypter implements Decrypter {
  private final SpeakEasyEccPrivateKey privateKey;
  private final StringEncoder stringEncoder;

  public ECIESDecrypter(final SpeakEasyEccPrivateKey privateKey) {
    this.stringEncoder = getSingleton();
    this.privateKey = privateKey;
  }

  public ECIESDecrypter(final SpeakEasyEccPrivateKey privateKey, final StringEncoder stringEncoder) {
    this.stringEncoder = stringEncoder;
    this.privateKey = privateKey;
  }

  @Override
  public String decrypt(final String message) {
    try {
      final IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
          new HMac(new SHA256Digest()), new GCMBufferedBlockCipher(new AESEngine()));
      final IESCipher cipher = new IESCipher(engine);
      final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      final byte[] messageBytes = stringEncoder.decodeStringToBytes(message);
      final byte[] nonce = new byte[GCM_NONCE_LENGTH];
      System.arraycopy(messageBytes, 0, nonce, 0, nonce.length);
      final IESParameterSpec parameterSpec = new IESParameterSpec(null, null, 128, 128, nonce);
      cipher.engineInit(Cipher.DECRYPT_MODE, privateKey.toKey(), parameterSpec, secureRandom);
      final byte[] cipherTextBytes = new byte[messageBytes.length - nonce.length];
      System.arraycopy(messageBytes, nonce.length, cipherTextBytes, 0, cipherTextBytes.length);
      final byte[] plainTextBytes = cipher.engineDoFinal(cipherTextBytes, 0, cipherTextBytes.length);
      final String plainText = stringEncoder.stringFromBytes(plainTextBytes);
      return plainText;
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException
        | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
