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

import com.github.exabrial.speakeasy.fingerprint.Blake2b384Fingerprinter;
import com.github.exabrial.speakeasy.testing.StringBytesEncoder;

public class Blake2b384FingerprinterTest {
	private final String testVector = "hello";
	private final String encodedTestVectorFingerprint = ("85f19170be541e7774da197c12ce959b91a280b2f23e3113d6638a3335507ed72ddc30f81244dbe9"
			+ "fa8d195c23bceb7e").toUpperCase();

	@Test
	public void testFingerprint() {
		final Blake2b384Fingerprinter fingerprinter = new Blake2b384Fingerprinter(new StringBytesEncoder());
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertEquals(encodedTestVectorFingerprint, fingerprint);
	}

	@Test
	public void testVerifyFingerprint() {
		final Blake2b384Fingerprinter fingerprinter = new Blake2b384Fingerprinter();
		final String fingerprint = fingerprinter.fingerprint(testVector);
		assertTrue(fingerprinter.verifyFingerprint(testVector, fingerprint));
	}
}
