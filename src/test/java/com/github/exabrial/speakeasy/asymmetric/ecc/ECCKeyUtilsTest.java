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

package com.github.exabrial.speakeasy.asymmetric.ecc;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class ECCKeyUtilsTest {
	private final ECCKeyUtils eccKeyUtils = new ECCKeyUtils();
	private final String publicKeyString = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsCn+KLhNmgacinopuRKAAlBKGbZ5zuFHkTD/s6mk3i21VdS4zk70l7dXp+yM"
			+ "tkdoUyPVsISwLO6ryVkX0wyLAQ==";
	private final String privateKeyString = "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCAXB74BNYk90OWLcs9eJOdp+o7+J/Va/Ge31Gitfrl/sg==";

	@Test
	public void testCreateKeyPair() {
		final SpeakEasyEccKeyPair createKeyPair = eccKeyUtils.createKeyPair();
		assertEquals("EC", createKeyPair.getPrivateKey().toKey().getAlgorithm());
		assertEquals("EC", createKeyPair.getPublicKey().toKey().getAlgorithm());
	}

	@Test
	public void testReadPublicKey_ToStringSpeakEasyEccPublicKey() {
		final SpeakEasyEccPublicKey readPublicKey = eccKeyUtils.readPublicKey(publicKeyString);
		final String toKeyString = eccKeyUtils.toString(readPublicKey);
		assertEquals(publicKeyString, toKeyString);
	}

	@Test
	public void testReadPrivateKey_ToStringSpeakEasyEccPrivateKey() {
		final SpeakEasyEccPrivateKey readPrivateKey = eccKeyUtils.readPrivateKey(privateKeyString);
		final String toKeyString = eccKeyUtils.toString(readPrivateKey);
		assertEquals(privateKeyString, toKeyString);
	}
}
