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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Locale;

import org.junit.Test;

import com.github.exabrial.speakeasy.encoding.HexStringEncoder;

public class SHA512FingerprinterTest {
	private final SHA512Fingerprinter fingerprinter = new SHA512Fingerprinter(HexStringEncoder.getSingleton());
	private final String testVetor = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private final String encodedTestVectorFingerprint = "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
			+ "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445";

	@Test
	public void testFingerprint() {
		String fingerprint = fingerprinter.fingerprint(testVetor);
		assertEquals(encodedTestVectorFingerprint.toUpperCase(Locale.US), fingerprint);
	}

	@Test
	public void testVerifyFingerprint() {
		String fingerprint = fingerprinter.fingerprint(testVetor);
		assertTrue(fingerprinter.verifyFingerprint(testVetor, fingerprint));
	}
}
