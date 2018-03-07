package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import org.junit.Test;

public class EccEncrypterTest {
	@Test
	public void testEncrypt() {
		EccKeyPairGenerator kpg = new EccKeyPairGenerator();
		SpeakEasyEccKeyPair keyPair = kpg.createKeyPair();
		EccEncrypter ecc = new EccEncrypter(keyPair.getPublicKey());
		String output = ecc.encrypt("plainText");
		System.out.println(output);

		EccDecrypter dcc = new EccDecrypter(keyPair.getPrivateKey());
		System.out.println(dcc.decrypt(output));
	}
}
