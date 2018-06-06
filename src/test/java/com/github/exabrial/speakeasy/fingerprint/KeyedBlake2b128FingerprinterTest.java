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

package com.github.exabrial.speakeasy.fingerprint;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

import com.github.exabrial.speakeasy.fingerprint.KeyedBlake2b128Fingerprinter;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey256;

public class KeyedBlake2b128FingerprinterTest {
	private final String testString = "I wanted to come up with a good construction joke... lets just say I'm working on it.";
	private final String expected = "MAw90TnS5pe2FZJbeRRVpw==";

	@Test
	void testFingerprintAndVerify() {
		final byte[] bytes = new byte[64];
		Arrays.fill(bytes, (byte) 1);
		final SymmetricKey256 key = new SymmetricKey256(bytes);
		final KeyedBlake2b128Fingerprinter fingerPrinter = new KeyedBlake2b128Fingerprinter(key);
		assertEquals(expected, fingerPrinter.fingerprint(testString));
		assertTrue(fingerPrinter.verifyFingerprint(testString, expected));
	}
}
