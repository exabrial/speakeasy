/* Copyright [2018] [Jonathan S. Fisher]
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

package com.github.exabrial.speakeasy.symmetric;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class SymmetricKeyUtilsTest {
	private final SymmetricKeyUtils symmetricKeyUtils = new SymmetricKeyUtils();
	private final String encodedKeyString = "Rtuvj4q7+QPzcjpwvgvJDA==";

	@Test
	public void testFromString_toString() {
		final SymmetricKey128 symmetricKey = symmetricKeyUtils.fromString(encodedKeyString);
		final String keyString = symmetricKeyUtils.toString(symmetricKey);
		assertEquals(encodedKeyString, keyString);
	}

	@Test
	public void testGenerateSecureSymmetricKey() {
		final SymmetricKey128 symmetricKey = symmetricKeyUtils.generateSecureSymmetricKey();
		assertEquals("AES", symmetricKey.toKey().getAlgorithm());
	}
}
