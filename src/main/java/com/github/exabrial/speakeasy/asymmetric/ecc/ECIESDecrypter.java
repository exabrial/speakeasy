package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.GCM_NONCE_LENGTH;
import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;

import com.github.exabrial.speakeasy.internal.GCMBufferedBlockCipher;
import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.primitives.encryption.Decrypter;

public class ECIESDecrypter implements Decrypter {
	private final SpeakEasyEccPrivateKey privateKey;
	private final StringEncoder stringEncoder;

	public ECIESDecrypter(final SpeakEasyEccPrivateKey privateKey) {
		this.stringEncoder = getSingleton();
		this.privateKey = privateKey;
	}

	public ECIESDecrypter(final SpeakEasyEccPrivateKey privateKey, final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
		this.privateKey = privateKey;
	}

	@Override
	public String decrypt(String message) {
		try {
			IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
					new HMac(new SHA256Digest()), new GCMBufferedBlockCipher(new AESEngine()));
			IESCipher cipher = new IESCipher(engine);
			SecureRandom secureRandom = SecureRandom.getInstanceStrong();
			byte[] messageBytes = stringEncoder.decodeBase64StringToBytes(message);
			byte[] nonce = new byte[GCM_NONCE_LENGTH];
			System.arraycopy(messageBytes, 0, nonce, 0, nonce.length);
			IESParameterSpec parameterSpec = new IESParameterSpec(null, null, 128, 128, nonce);
			cipher.engineInit(Cipher.DECRYPT_MODE, privateKey.toKey(), parameterSpec, secureRandom);
			byte[] cipherTextBytes = new byte[messageBytes.length - nonce.length];
			System.arraycopy(messageBytes, nonce.length, cipherTextBytes, 0, cipherTextBytes.length);
			byte[] plainTextBytes = cipher.engineDoFinal(cipherTextBytes, 0, cipherTextBytes.length);
			String plainText = stringEncoder.stringFromBytes(plainTextBytes);
			return plainText;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
