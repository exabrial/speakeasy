package com.github.exabrial.speakeasy.asymmetric.ecc;

import org.junit.Test;

public class ECDSASignerTest {

	@Test
	public void testSignPayload() {
		ECCKeyUtils utils = new ECCKeyUtils();
		SpeakEasyEccKeyPair keyPair = utils.createKeyPair();
		ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		String payload = "payload";
		String signatureText = signer.signPayload(payload);
		ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		System.out.println(signatureText);
		System.out.println(verifier.verifyPayloadSignature(payload, signatureText));
	}

}
