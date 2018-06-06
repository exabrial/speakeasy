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

import com.github.exabrial.speakeasy.fingerprint.Blake2b512Fingerprinter;
import com.github.exabrial.speakeasy.testing.StringBytesEncoder;

public class Blake2b512FingerprinterTest {
	private final String testVector = "hello";
	private final String encodedTestVectorFingerprint = ("e4cfa39a3d37be31c59609e807970799caa68a19bfaa15135f165085e01d41a65ba1e1b146aeb6bd"
			+ "0092b49eac214c103ccfa3a365954bbbe52f74a2b3620c94").toUpperCase();

	@Test
	public void testFingerprint() {
		final Blake2b512Fingerprinter fingerprinter = new Blake2b512Fingerprinter(new StringBytesEncoder());
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertEquals(encodedTestVectorFingerprint, fingerprint);
	}

	@Test
	public void testVerifyFingerprint() {
		final Blake2b512Fingerprinter fingerprinter = new Blake2b512Fingerprinter();
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertTrue(fingerprinter.verifyFingerprint(testVector, fingerprint));
	}
}
