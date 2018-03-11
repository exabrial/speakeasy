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
import com.github.exabrial.speakeasy.primitives.encryption.Encrypter;

public class ECIESEncrypter implements Encrypter {
	private final SpeakEasyEccPublicKey publicKey;
	private final StringEncoder stringEncoder;

	public ECIESEncrypter(final SpeakEasyEccPublicKey publicKey) {
		this.stringEncoder = getSingleton();
		this.publicKey = publicKey;
	}

	public ECIESEncrypter(final SpeakEasyEccPublicKey publicKey, final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
		this.publicKey = publicKey;
	}

	@Override
	public String encrypt(final String plainText) {
		try {
			IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
					new HMac(new SHA256Digest()), new GCMBufferedBlockCipher(new AESEngine()));
			IESCipher cipher = new IESCipher(engine);
			SecureRandom secureRandom = SecureRandom.getInstanceStrong();
			byte[] nonce = new byte[GCM_NONCE_LENGTH];
			secureRandom.nextBytes(nonce);
			IESParameterSpec parameterSpec = new IESParameterSpec(null, null, 128, 128, nonce);
			cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey.toKey(), parameterSpec, secureRandom);
			byte[] plainTextBytes = stringEncoder.getStringAsBytes(plainText);
			byte[] cipherTextBytes = cipher.engineDoFinal(plainTextBytes, 0, plainTextBytes.length);
			byte[] ivAndCipherText = new byte[nonce.length + cipherTextBytes.length];
			System.arraycopy(nonce, 0, ivAndCipherText, 0, nonce.length);
			System.arraycopy(cipherTextBytes, 0, ivAndCipherText, nonce.length, cipherTextBytes.length);
			String encodedmessage = stringEncoder.encodeBytesAsBase64(ivAndCipherText);
			return encodedmessage;
		} catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException
				| InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
