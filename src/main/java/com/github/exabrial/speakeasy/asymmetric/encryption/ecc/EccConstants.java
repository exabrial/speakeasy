package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

import com.github.exabrial.speakeasy.primitaves.SpeakEasyKey;

public final class EccConstants {
	protected static final String GEN_ALG = "EC";
	protected static final String ENCRYPTION_SCHEME = "ECIESwithAES-CBC";
	protected static final String EC_CURVE_NAME = "secp256r1";
	protected static final byte[] FIXED_IV;

	static {
		if (Arrays.asList(Security.getProviders()).stream()
				.filter(provider -> provider.getName().equals(BouncyCastleProvider.PROVIDER_NAME)).findFirst()
				.orElse(null) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		FIXED_IV = new byte[16];
		Arrays.fill(FIXED_IV, (byte) 0);
	}

	private EccConstants() {
	}

	protected static Cipher createCipher(SpeakEasyKey speakEasyKey) throws NoSuchAlgorithmException,
			NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(ENCRYPTION_SCHEME, BouncyCastleProvider.PROVIDER_NAME);
		IESParameterSpec param = new IESParameterSpec(null, null, 256, 128, FIXED_IV);
		if (speakEasyKey instanceof SpeakEasyEccPublicKey) {
			cipher.init(Cipher.ENCRYPT_MODE, speakEasyKey.toKey(), param, SecureRandom.getInstanceStrong());
		} else if (speakEasyKey instanceof SpeakEasyEccPrivateKey) {
			cipher.init(Cipher.DECRYPT_MODE, speakEasyKey.toKey(), param, SecureRandom.getInstanceStrong());
		}
		return cipher;
	}
}
