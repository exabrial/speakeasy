package com.github.exabrial.speakeasy.symmetric;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES_KEY_SIZE;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.PKDF;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.PKDF_ITERATIONS;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.BitSet;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKeyUtils {
	private final SecureRandom secureRandom;

	public SymmetricKeyUtils() {
		try {
			secureRandom = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public SymmetricKey createFromPassword(String password) {
		try {
			BitSet bitSet = new BitSet(128);
			bitSet.set(0, 127);
			KeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), bitSet.toByteArray(), PKDF_ITERATIONS,
					AES_KEY_SIZE);
			SecretKeyFactory factory = SecretKeyFactory.getInstance(PKDF);
			SecretKey pkdfKey = factory.generateSecret(pbeKeySpec);
			SecretKey secretKey = new SecretKeySpec(pkdfKey.getEncoded(), 0, pkdfKey.getEncoded().length, AES);
			return new SymmetricKey(secretKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	public SymmetricKey generateSecureSymmetricKey() {
		try {
			KeyGenerator keyGen = KeyGenerator.getInstance(AES);
			keyGen.init(AES_KEY_SIZE, secureRandom);
			SecretKey secretKey;
			synchronized (secureRandom) {
				secretKey = keyGen.generateKey();
			}
			return new SymmetricKey(secretKey);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
