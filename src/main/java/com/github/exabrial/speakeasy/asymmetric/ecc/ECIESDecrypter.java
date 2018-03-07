/**
 * 
 */
package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import com.github.exabrial.speakeasy.internal.SpeakEasyCipher;
import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.primitives.encryption.Decrypter;

public class ECIESDecrypter implements Decrypter {
	private final StringEncoder stringEncoder;
	private final SpeakEasyEccPrivateKey privateKey;

	public ECIESDecrypter(final SpeakEasyEccPrivateKey privateKey) {
		this.stringEncoder = getSingleton();
		this.privateKey = privateKey;
	}

	public ECIESDecrypter(final StringEncoder stringEncoder, final SpeakEasyEccPrivateKey privateKey) {
		this.stringEncoder = stringEncoder;
		this.privateKey = privateKey;
	}

	@Override
	public String decrypt(String cipherText) {
		SpeakEasyCipher eccCipher = new SpeakEasyCipher(privateKey);
		byte[] cipherTextBytes = stringEncoder.decodeBase64StringToBytes(cipherText);
		byte[] plainTextBytes = eccCipher.doFinal(cipherTextBytes);
		return stringEncoder.stringFromBytes(plainTextBytes);
	}

}
