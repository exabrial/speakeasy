package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.ECCConstants.*;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyKeyPairGenerator;

public class ECCKeyPairGenerator implements SpeakEasyKeyPairGenerator {
	private final SecureRandom secureRandom;

	public ECCKeyPairGenerator() {
		try {
			secureRandom = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyEccKeyPair createKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(GEN_ALG);
			ECGenParameterSpec ecSpec = new ECGenParameterSpec(EC_CURVE_NAME);
			keyGen.initialize(ecSpec, secureRandom);
			KeyPair jceKeyPair;
			synchronized (secureRandom) {
				jceKeyPair = keyGen.generateKeyPair();
			}
			SpeakEasyEccKeyPair keyPair = new SpeakEasyEccKeyPair(jceKeyPair);
			return keyPair;
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}
}
