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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.primitives.Fingerprinter;

public class SHA256Fingerprinter implements Fingerprinter {
  private final StringEncoder stringEncoder;

  public SHA256Fingerprinter() {
    this.stringEncoder = Base64StringEncoder.getSingleton();
  }

  public SHA256Fingerprinter(final StringEncoder stringEncoder) {
    this.stringEncoder = stringEncoder;
  }

  @Override
  public String fingerprint(final String message) {
    final byte[] fingerprintBytes = digest(message);
    final String fingerprint = stringEncoder.encodeBytesAsString(fingerprintBytes);
    return fingerprint;
  }

  @Override
  public boolean verifyFingerprint(final String message, final String fingerprint) {
    final byte[] cfingerprintBytes = digest(message);
    final byte[] pFingerprintBytes = stringEncoder.decodeStringToBytes(fingerprint);
    final boolean equals = Arrays.equals(cfingerprintBytes, pFingerprintBytes);
    return equals;
  }

  private byte[] digest(final String message) {
    try {
      final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
      final MessageDigest digest = MessageDigest.getInstance(SHA256);
      final byte[] fingerprintBytes = digest.digest(messageBytes);
      return fingerprintBytes;
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
