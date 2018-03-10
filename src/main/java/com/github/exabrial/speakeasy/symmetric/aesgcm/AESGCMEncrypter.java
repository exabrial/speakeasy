package com.github.exabrial.speakeasy.symmetric.aesgcm;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES_GCM;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.GCM_NONCE_LENGTH;
import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.primitives.encryption.Encrypter;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey;

public class AESGCMEncrypter implements Encrypter {

	private final StringEncoder stringEncoder;
	private final SymmetricKey sharedKey;

	public AESGCMEncrypter(final SymmetricKey sharedKey) {
		this.stringEncoder = getSingleton();
		this.sharedKey = sharedKey;
	}

	public AESGCMEncrypter(final SymmetricKey sharedKey, final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
		this.sharedKey = sharedKey;
	}

	@Override
	public String encrypt(String plainText) {
		try {
			Cipher cipher = Cipher.getInstance(AES_GCM);
			byte iv[] = new byte[GCM_NONCE_LENGTH];
			SecureRandom secureRandom = SecureRandom.getInstanceStrong();
			secureRandom.nextBytes(iv);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
			cipher.init(Cipher.ENCRYPT_MODE, sharedKey.toKey(), gcmSpec, secureRandom);
			byte[] plainTextBytes = stringEncoder.getStringAsBytes(plainText);
			byte[] cipherTextBytes = cipher.doFinal(plainTextBytes);
			byte[] ivAndCipherText = new byte[iv.length + cipherTextBytes.length];
			System.arraycopy(iv, 0, ivAndCipherText, 0, iv.length);
			System.arraycopy(cipherTextBytes, 0, ivAndCipherText, iv.length, cipherTextBytes.length);
			String encodedmessage = stringEncoder.encodeBytesAsBase64(ivAndCipherText);
			return encodedmessage;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}
}
