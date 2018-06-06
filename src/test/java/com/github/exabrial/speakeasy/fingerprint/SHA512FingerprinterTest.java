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
import com.github.exabrial.speakeasy.fingerprint.SHA512Fingerprinter;

public class SHA512FingerprinterTest {
	private final SHA512Fingerprinter fingerprinter = new SHA512Fingerprinter(HexStringEncoder.getSingleton());
	private final String testVector = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	private final String encodedTestVectorFingerprint = ("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c335"
			+ "96fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445").toUpperCase();

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
