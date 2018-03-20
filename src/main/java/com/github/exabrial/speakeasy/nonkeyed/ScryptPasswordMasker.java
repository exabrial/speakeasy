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
package com.github.exabrial.speakeasy.nonkeyed;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_N;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_P;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_R;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_SIZE;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.SCrypt;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.misc.ConstantTimeMessageComporator;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.PasswordMasker;

public class ScryptPasswordMasker implements PasswordMasker {

  private final StringEncoder stringEncoder;
  private final MessageComporator messageComporator;

  public ScryptPasswordMasker() {
    this.stringEncoder = Base64StringEncoder.getSingleton();
    this.messageComporator = ConstantTimeMessageComporator.getSingleton();
  }

  public ScryptPasswordMasker(final StringEncoder stringEncoder, final MessageComporator messageComporator) {
    this.stringEncoder = stringEncoder;
    this.messageComporator = messageComporator;
  }

  @Override
  public String maskPassword(final String message) {
    try {
      final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
      final byte[] saltBytes = new byte[16];
      final SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      secureRandom.nextBytes(saltBytes);
      final byte[] scryptBytes = scrypt(messageBytes, saltBytes);
      final String scrypt = stringEncoder.encodeBytesAsString(scryptBytes);
      final String salt = stringEncoder.encodeBytesAsString(saltBytes);
      final String hash = scrypt + ":" + salt;
      return hash;
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public boolean checkPassword(final String password, final String signature) {
    final byte[] messageBytes = stringEncoder.getStringAsBytes(password);
    final String[] signatureSplit = signature.split(":");
    final byte[] pScryptBytes = stringEncoder.decodeStringToBytes(signatureSplit[0]);
    final byte[] saltBytes = stringEncoder.decodeStringToBytes(signatureSplit[1]);
    final byte[] cScryptBytes = scrypt(messageBytes, saltBytes);
    return messageComporator.compare(stringEncoder.encodeBytesAsString(cScryptBytes),
        stringEncoder.encodeBytesAsString(pScryptBytes));
  }

  private byte[] scrypt(final byte[] messageBytes, final byte[] saltBytes) {
    final byte[] scryptBytes = SCrypt.generate(messageBytes, saltBytes, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_SIZE);
    return scryptBytes;
  }
}
