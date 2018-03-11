package com.github.exabrial.speakeasy.asymmetric.ecc;

import org.junit.Test;

public class ECDSASignerTest {
	@Test
	public void testSignmessage() {
		ECCKeyUtils utils = new ECCKeyUtils();
		SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		String message = "message";
		String signatureText = signer.signmessage(message);
		ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		System.out.println(signatureText);
		System.out.println(verifier.verifymessageSignature(message, signatureText));
	}
}
