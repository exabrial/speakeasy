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

package com.github.exabrial.speakeasy.asymmetric.rsa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class RSATest {
	private final String message = "I got fired from a bank once. A lady asked me to check her balance and I gave her a shove.";
	private final RSAKeyUtils utils = new RSAKeyUtils();
	private final SpeakEasyRSAKeyPair keyPair = utils.createKeyPair();

	@Test
	public void testSignmessage() {
		final RSASigner signer = new RSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final RSAVerifier verifier = new RSAVerifier(keyPair.getPublicKey());
		assertTrue(verifier.verifyMessageSignature(message, signatureText));
	}

	@Test
	public void testSignmessage_modMessage() {
		final RSASigner signer = new RSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final RSAVerifier verifier = new RSAVerifier(keyPair.getPublicKey());
		assertFalse(verifier.verifyMessageSignature(message + " ", signatureText));
	}

	@Test
	public void testSignmessage_modMessage2() {
		final RSASigner signer = new RSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final RSAVerifier verifier = new RSAVerifier(keyPair.getPublicKey());
		assertFalse(verifier.verifyMessageSignature(message.replaceFirst("once", "Once"), signatureText));
	}

	@Test
	public void testSignmessage_modSig() {
		final RSASigner signer = new RSASigner(keyPair.getPrivateKey());
		final String signatureText = signer.signMessage(message);
		final RSAVerifier verifier = new RSAVerifier(keyPair.getPublicKey());
		final char newChar = (char) (signatureText.charAt(5) + 1);
		assertFalse(verifier.verifyMessageSignature(message, signatureText.replace(signatureText.charAt(5), newChar)));
	}
}