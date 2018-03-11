package com.github.exabrial.speakeasy.symmetric.aesgcm;

import org.junit.Test;

import com.github.exabrial.speakeasy.symmetric.SymmetricKey;
import com.github.exabrial.speakeasy.symmetric.SymmetricKeyUtils;

public class AESGCMEncrypterTest {

	@Test
	public void testEncrypt() throws Exception {
		SymmetricKeyUtils utils = new SymmetricKeyUtils();
		SymmetricKey sharedKey = utils.createFromPassword("password");
		AESGCMEncrypter encrypter = new AESGCMEncrypter(sharedKey);
		String cipherText = encrypter.encrypt("0123456789abcdef");
		sharedKey = utils.createFromPassword("password");
		System.out.println(cipherText);
		AESGCMDecrypter decrypter = new AESGCMDecrypter(sharedKey);
		System.out.println(decrypter.decrypt(cipherText));
	}

}
