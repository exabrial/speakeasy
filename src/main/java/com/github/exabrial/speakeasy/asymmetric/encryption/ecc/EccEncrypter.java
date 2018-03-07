package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.createCipher;
import static com.github.exabrial.speakeasy.primitaves.Base64StringEncoder.getSingleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.exabrial.speakeasy.asymmetric.encryption.ASymmetricEncrypter;
import com.github.exabrial.speakeasy.primitaves.StringEncoder;

public class EccEncrypter implements ASymmetricEncrypter {
	private final StringEncoder stringEncoder;
	private final SpeakEasyEccPublicKey publicKey;

	public EccEncrypter(final SpeakEasyEccPublicKey publicKey) {
		this.stringEncoder = getSingleton();
		this.publicKey = publicKey;
	}

	public EccEncrypter(final StringEncoder stringEncoder, final SpeakEasyEccPublicKey publicKey) {
		this.stringEncoder = stringEncoder;
		this.publicKey = publicKey;
	}

	@Override
	public String encrypt(final String plainText) {
		try {
			Cipher eccCipher = createCipher(publicKey);
			byte[] plainTextBytes = stringEncoder.getStringAsBytes(plainText);
			byte[] cipherTextBytes = eccCipher.doFinal(plainTextBytes);
			return stringEncoder.encodeBytesAsBase64(cipherTextBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}
}
