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

package com.github.exabrial.speakeasy.asymmetric.ecc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ECDSASignerTest {
	final String message = "I was asked to name all the presidents. I thought they already had names.";

	@Test
	public void testSignmessage() {
		final ECCKeyUtils utils = new ECCKeyUtils();
		final SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		final ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		assertTrue(verifier.verifyMessageSignature(message, signatureText));
	}

	@Test
	public void testSignmessage_modMessage() {
		final ECCKeyUtils utils = new ECCKeyUtils();
		final SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		final ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		assertFalse(verifier.verifyMessageSignature(message + " ", signatureText));
	}

	@Test
	public void testSignmessage_modMessage2() {
		final ECCKeyUtils utils = new ECCKeyUtils();
		final SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		final ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		assertFalse(verifier.verifyMessageSignature(message.replaceFirst("was", "Was"), signatureText));
	}

	@Test
	public void testSignmessage_modSig() {
		final ECCKeyUtils utils = new ECCKeyUtils();
		final SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		final ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		final char newChar = (char) (signatureText.charAt(5) + 1);
		assertFalse(verifier.verifyMessageSignature(message, signatureText.replace(signatureText.charAt(5), newChar)));
	}
}
