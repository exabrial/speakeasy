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

import org.junit.jupiter.api.Test;

import com.github.exabrial.speakeasy.encoding.HexStringEncoder;
import com.github.exabrial.speakeasy.fingerprint.SHA256Fingerprinter;

public class SHA256FingerprinterTest {
	private final SHA256Fingerprinter fingerprinter = new SHA256Fingerprinter(HexStringEncoder.getSingleton());
	private final String testVector = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private final String encodedTestVectorFingerprint = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1".toUpperCase();

	@Test
	public void testFingerprint() {
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertEquals(encodedTestVectorFingerprint, fingerprint);
	}

	@Test
	public void testVerifyFingerprint() {
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertTrue(fingerprinter.verifyFingerprint(testVector, fingerprint));
	}
}
