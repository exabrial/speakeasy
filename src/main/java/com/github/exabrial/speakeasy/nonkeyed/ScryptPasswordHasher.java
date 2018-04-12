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

import java.security.SecureRandom;

import org.bouncycastle.crypto.generators.SCrypt;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.misc.ConstantTimeMessageComporator;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.PasswordHasher;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_N;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_P;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_R;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SCRYPT_SIZE;

public class ScryptPasswordHasher implements PasswordHasher {
  private static final int SALT_BYTES_LENGTH = 32;
  private final StringEncoder stringEncoder;
  private final MessageComporator passwordComporator;
  private final SecureRandomProvider secureRandomProvider;

  public ScryptPasswordHasher() {
    this.stringEncoder = Base64StringEncoder.getSingleton();
    this.passwordComporator = ConstantTimeMessageComporator.getSingleton();
    this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
  }

  public ScryptPasswordHasher(final StringEncoder stringEncoder, final MessageComporator passwordComporator,
      final SecureRandomProvider secureRandomProvider) {
    this.stringEncoder = stringEncoder;
    this.passwordComporator = passwordComporator;
    this.secureRandomProvider = secureRandomProvider;
  }

  @Override
  public String hashPassword(final String password) {
    final byte[] passwordBytes = stringEncoder.getStringAsBytes(password);
    final byte[] saltBytes = new byte[SALT_BYTES_LENGTH];
    final SecureRandom secureRandom = secureRandomProvider.borrowSecureRandom();
    secureRandom.nextBytes(saltBytes);
    final byte[] scryptBytes = scrypt(passwordBytes, saltBytes);
    final byte[] hashBytes = new byte[SALT_BYTES_LENGTH + scryptBytes.length];
    System.arraycopy(saltBytes, 0, hashBytes, 0, SALT_BYTES_LENGTH);
    System.arraycopy(scryptBytes, 0, hashBytes, SALT_BYTES_LENGTH, scryptBytes.length);
    final String hash = stringEncoder.encodeBytesAsString(hashBytes);
    return hash;
  }

  @Override
  public boolean checkPassword(final String password, final String hash) {
    try {
      final byte[] passwordBytes = stringEncoder.getStringAsBytes(password);
      final byte[] hashBytes = stringEncoder.decodeStringToBytes(hash);
      final byte[] saltBytes = new byte[SALT_BYTES_LENGTH];
      System.arraycopy(hashBytes, 0, saltBytes, 0, SALT_BYTES_LENGTH);
      final byte[] pScryptBytes = new byte[hashBytes.length - SALT_BYTES_LENGTH];
      System.arraycopy(hashBytes, SALT_BYTES_LENGTH, pScryptBytes, 0, pScryptBytes.length);
      final byte[] cScryptBytes = scrypt(passwordBytes, saltBytes);
      return passwordComporator.compare(stringEncoder.encodeBytesAsString(cScryptBytes),
          stringEncoder.encodeBytesAsString(pScryptBytes));
    } catch (final NullPointerException | ArrayIndexOutOfBoundsException e) {
      return false;
    }
  }

  private byte[] scrypt(final byte[] passwordBytes, final byte[] saltBytes) {
    final byte[] scryptBytes = SCrypt.generate(passwordBytes, saltBytes, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_SIZE);
    return scryptBytes;
  }
}
