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

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.internal.GCMBufferedBlockCipher;
import com.github.exabrial.speakeasy.primitives.Encrypter;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.IES_PARAMATER_SPEC;

public class ECIESEncrypter implements Encrypter {
  private final SpeakEasyEccPublicKey publicKey;
  private final StringEncoder stringEncoder;
  private final SecureRandomProvider secureRandomProvider;

  public ECIESEncrypter(final SpeakEasyEccPublicKey publicKey) {
    this.publicKey = publicKey;
    this.stringEncoder = Base64StringEncoder.getSingleton();
    this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
  }

  public ECIESEncrypter(final SpeakEasyEccPublicKey publicKey, final StringEncoder stringEncoder,
      final SecureRandomProvider secureRandomProvider) {
    this.publicKey = publicKey;
    this.stringEncoder = stringEncoder;
    this.secureRandomProvider = secureRandomProvider;
  }

  @Override
  public String encrypt(final String plainText) {
    try {
      final IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
          new HMac(new SHA256Digest()), new GCMBufferedBlockCipher(new AESEngine()));
      final IESCipher cipher = new IESCipher(engine);
      final SecureRandom secureRandom = secureRandomProvider.borrowSecureRandom();
      cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey.toKey(), IES_PARAMATER_SPEC, secureRandom);
      final byte[] plainTextBytes = stringEncoder.getStringAsBytes(plainText);
      final byte[] cipherTextBytes = cipher.engineDoFinal(plainTextBytes, 0, plainTextBytes.length);
      final String cipherText = stringEncoder.encodeBytesAsString(cipherTextBytes);
      return cipherText;
    } catch (InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }
}
