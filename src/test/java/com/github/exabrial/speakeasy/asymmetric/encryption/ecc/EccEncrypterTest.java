package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import org.junit.Test;

import com.github.exabrial.speakeasy.asymmetric.ecc.ECIESDecrypter;
import com.github.exabrial.speakeasy.asymmetric.ecc.ECIESEncrypter;
import com.github.exabrial.speakeasy.asymmetric.ecc.ECCKeyPairGenerator;
import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccKeyPair;

public class EccEncrypterTest {
	@Test
	public void testEncrypt() {
		ECCKeyPairGenerator kpg = new ECCKeyPairGenerator();
		SpeakEasyEccKeyPair keyPair = kpg.createKeyPair();
		ECIESEncrypter ecc = new ECIESEncrypter(keyPair.getPublicKey());
		String output = ecc.encrypt("plainText");
		System.out.println(output);

		ECIESDecrypter dcc = new ECIESDecrypter(keyPair.getPrivateKey());
		System.out.println(dcc.decrypt(output));
	}
}
