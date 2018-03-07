package com.github.exabrial.speakeasy.asymmetric.ecc;

import org.junit.Test;

public class ECDSASignerTest {

	@Test
	public void testSignPayload() {
		ECCKeyPairGenerator kpg = new ECCKeyPairGenerator();
		SpeakEasyEccKeyPair keyPair = kpg.createKeyPair();
		ECDSASigner signer = new ECDSASigner(keyPair.getPrivateKey());
		String payload = "payload";
		String signatureText = signer.signPayload(payload);
		ECDSAVerifier verifier = new ECDSAVerifier(keyPair.getPublicKey());
		System.out.println(signatureText);
		System.out.println(verifier.verifyPayloadSignature(payload, signatureText));
	}

}
