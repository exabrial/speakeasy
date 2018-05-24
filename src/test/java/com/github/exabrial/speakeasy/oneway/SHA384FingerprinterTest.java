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

package com.github.exabrial.speakeasy.oneway;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.github.exabrial.speakeasy.encoding.HexStringEncoder;

public class SHA384FingerprinterTest {
	private SHA384Fingerprinter fingerprinter = new SHA384Fingerprinter(HexStringEncoder.getSingleton());
	private String testVector = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private String encodedTestVectorFingerprint = ("3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05ab"
			+ "fe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b").toUpperCase();

	@Test
	public void testFingerprint() {
		String fingerprint = fingerprinter.fingerprint(testVector);
		assertEquals(encodedTestVectorFingerprint, fingerprint);
	}

	@Test
	public void testVerifyFingerprint() {
		String fingerprint = fingerprinter.fingerprint(testVector);
		assertTrue(fingerprinter.verifyFingerprint(testVector, fingerprint));
	}
}
