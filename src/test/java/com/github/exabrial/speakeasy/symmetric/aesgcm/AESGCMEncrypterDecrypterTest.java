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

package com.github.exabrial.speakeasy.symmetric.aesgcm;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import org.junit.jupiter.api.Test;

import com.github.exabrial.speakeasy.symmetric.SymmetricKey128;
import com.github.exabrial.speakeasy.symmetric.SymmetricKeyUtils;

public class AESGCMEncrypterDecrypterTest {
	private final String plainText = "Never iron a four leaf clover... you don't want to press your luck";

	@Test
	public void testEncryptDecrypt() throws Exception {
		final SymmetricKeyUtils utils = new SymmetricKeyUtils();
		final SymmetricKey128 sharedKey = utils.generateSecureSymmetricKey(SymmetricKey128.class);
		final AESGCMEncrypter encrypter = new AESGCMEncrypter(sharedKey);
		final String cipherText = encrypter.encrypt(plainText);
		final AESGCMDecrypter decrypter = new AESGCMDecrypter(sharedKey);
		assertEquals(plainText, decrypter.decrypt(cipherText));
	}

	@Test
	public void testEncrypt_doesntProduceSameCiphertext() throws Exception {
		final SymmetricKeyUtils utils = new SymmetricKeyUtils();
		final SymmetricKey128 sharedKey = utils.generateSecureSymmetricKey(SymmetricKey128.class);
		final AESGCMEncrypter encrypter = new AESGCMEncrypter(sharedKey);
		final String cipherText0 = encrypter.encrypt(plainText);
		final String cipherText1 = encrypter.encrypt(plainText);
		assertNotEquals(cipherText0, cipherText1);
	}
}
