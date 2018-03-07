package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import com.github.exabrial.speakeasy.internal.SpeakEasyCipher;
import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.primitives.encryption.Encrypter;

public class ECIESEncrypter implements Encrypter {
	private final StringEncoder stringEncoder;
	private final SpeakEasyEccPublicKey publicKey;

	public ECIESEncrypter(final SpeakEasyEccPublicKey publicKey) {
		this.stringEncoder = getSingleton();
		this.publicKey = publicKey;
	}

	public ECIESEncrypter(final StringEncoder stringEncoder, final SpeakEasyEccPublicKey publicKey) {
		this.stringEncoder = stringEncoder;
		this.publicKey = publicKey;
	}

	@Override
	public String encrypt(final String plainText) {
		SpeakEasyCipher eccCipher = new SpeakEasyCipher(publicKey);
		byte[] plainTextBytes = stringEncoder.getStringAsBytes(plainText);
		byte[] cipherTextBytes = eccCipher.doFinal(plainTextBytes);
		return stringEncoder.encodeBytesAsBase64(cipherTextBytes);
	}
}
