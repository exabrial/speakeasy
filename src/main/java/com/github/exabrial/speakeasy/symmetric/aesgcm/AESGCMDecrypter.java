package com.github.exabrial.speakeasy.symmetric.aesgcm;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES_GCM;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES_GCM_TAG_LENGTH;
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
import com.github.exabrial.speakeasy.primitives.encryption.Decrypter;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey;

public class AESGCMDecrypter implements Decrypter {
	private final StringEncoder stringEncoder;
	private final SymmetricKey sharedKey;

	public AESGCMDecrypter(final SymmetricKey sharedKey) {
		this.stringEncoder = getSingleton();
		this.sharedKey = sharedKey;
	}

	public AESGCMDecrypter(final SymmetricKey sharedKey, final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
		this.sharedKey = sharedKey;
	}

	@Override
	public String decrypt(String message) {
		try {
			byte[] messageBytes = stringEncoder.decodeBase64StringToBytes(message);
			byte[] iv = new byte[GCM_NONCE_LENGTH];
			System.arraycopy(messageBytes, 0, iv, 0, iv.length);
			GCMParameterSpec gcmSpec = new GCMParameterSpec(AES_GCM_TAG_LENGTH, iv);
			Cipher cipher = Cipher.getInstance(AES_GCM);
			cipher.init(Cipher.DECRYPT_MODE, sharedKey.toKey(), gcmSpec, SecureRandom.getInstanceStrong());
			byte[] cipherTextBytes = new byte[messageBytes.length - iv.length];
			System.arraycopy(messageBytes, iv.length, cipherTextBytes, 0, cipherTextBytes.length);
			byte[] plainTextBytes = cipher.doFinal(cipherTextBytes);
			String plainText = stringEncoder.stringFromBytes(plainTextBytes);
			return plainText;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			throw new RuntimeException(e);
		}
	}
}
