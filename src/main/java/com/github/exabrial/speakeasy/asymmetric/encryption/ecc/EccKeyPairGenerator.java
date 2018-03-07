package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.EC_CURVE_NAME;
import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.GEN_ALG;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyKeyPairGenerator;

public class EccKeyPairGenerator implements SpeakEasyKeyPairGenerator {
	private final SecureRandom secureRandom;

	public EccKeyPairGenerator() {
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
