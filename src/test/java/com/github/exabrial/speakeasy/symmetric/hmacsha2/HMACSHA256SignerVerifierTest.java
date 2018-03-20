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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.github.exabrial.speakeasy.symmetric.SymmetricKey;
import com.github.exabrial.speakeasy.symmetric.SymmetricKeyUtils;

public class HMACSHA256SignerVerifierTest {
  final String message = "The best thing about a boolean is even if you are wrong, you are only off by a bit.";

  @Test
  public void testVerifyMessageSignature() {
    final SymmetricKeyUtils utils = new SymmetricKeyUtils();
    final SymmetricKey key = utils.generateSecureSymmetricKey();
    final HMACSHA256SignerVerifier sv = new HMACSHA256SignerVerifier(key);
    final String signature = sv.fingerprint(message);
    assertTrue(sv.verifyFingerprint(message, signature));
  }

  @Test
  public void testVerifyMessageSignature_modifiedSignature() {
    final SymmetricKeyUtils utils = new SymmetricKeyUtils();
    final SymmetricKey key = utils.generateSecureSymmetricKey();
    final HMACSHA256SignerVerifier sv = new HMACSHA256SignerVerifier(key);
    final String signature = sv.fingerprint(message);
    assertFalse(sv.verifyFingerprint(message, "P" + signature));
  }

  @Test
  public void testVerifyMessageSignature_notBase64() {
    final SymmetricKeyUtils utils = new SymmetricKeyUtils();
    final SymmetricKey key = utils.generateSecureSymmetricKey();
    final HMACSHA256SignerVerifier sv = new HMACSHA256SignerVerifier(key);
    assertFalse(sv.verifyFingerprint(message, "I'm not base64 at all! haha"));
  }

  @Test
  public void testVerifyMessageSignature_base64ButInvalid() {
    final SymmetricKeyUtils utils = new SymmetricKeyUtils();
    final SymmetricKey key = utils.generateSecureSymmetricKey();
    final HMACSHA256SignerVerifier sv = new HMACSHA256SignerVerifier(key);
    assertFalse(sv.verifyFingerprint(message, "ZG9uJ3QgdHJ5IHRoaXMgYXQgaG9tZQ=="));
  }
}
