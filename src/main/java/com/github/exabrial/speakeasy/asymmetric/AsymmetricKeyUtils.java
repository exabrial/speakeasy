package com.github.exabrial.speakeasy.asymmetric;

import static com.github.exabrial.speakeasy.internal.ECCConstants.GEN_ALG;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccKeyPair;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public interface AsymmetricKeyUtils {
	SpeakEasyKeyPair createKeyPair();

	SpeakEasyPublicKey readPublicKey(String encodedKeyText);

	SpeakEasyPrivateKey readPrivateKey(String encodedKeyText);

	StringEncoder getStringEncoder();

	default public String toString(SpeakEasyPublicKey speakEasyPublicKey) {
		try {
			String alg;
			if (speakEasyPublicKey instanceof SpeakEasyEccKeyPair) {
				alg = GEN_ALG;
			} else {
				throw new RuntimeException("unsupported key type");
			}
			KeyFactory keyFactory = KeyFactory.getInstance(alg);
			EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPublicKey.toKey(), X509EncodedKeySpec.class);
			return getStringEncoder().encodeBytesAsBase64(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	default public String toString(SpeakEasyPrivateKey speakEasyPrivateKey) {
		try {
			String alg;
			if (speakEasyPrivateKey instanceof SpeakEasyEccKeyPair) {
				alg = GEN_ALG;
			} else {
				throw new RuntimeException("unsupported key type");
			}
			KeyFactory keyFactory = KeyFactory.getInstance(alg);
			EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPrivateKey.toKey(), PKCS8EncodedKeySpec.class);
			return getStringEncoder().encodeBytesAsBase64(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
}
