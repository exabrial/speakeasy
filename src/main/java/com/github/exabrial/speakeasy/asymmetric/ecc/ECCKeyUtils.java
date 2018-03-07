package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.ECCConstants.EC_CURVE_NAME;
import static com.github.exabrial.speakeasy.internal.ECCConstants.GEN_ALG;
import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.github.exabrial.speakeasy.asymmetric.AsymmetricKeyUtils;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECCKeyUtils implements AsymmetricKeyUtils {
	private final StringEncoder stringEncoder;
	private final SecureRandom secureRandom;

	public ECCKeyUtils() {
		try {
			this.stringEncoder = getSingleton();
			this.secureRandom = SecureRandom.getInstanceStrong();
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public ECCKeyUtils(StringEncoder stringEncoder) {
		try {
			this.stringEncoder = stringEncoder;
			this.secureRandom = SecureRandom.getInstanceStrong();
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
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyEccPublicKey readPublicKey(String encodedKeyText) {
		try {
			byte[] encodedKeyBytes = stringEncoder.decodeBase64StringToBytes(encodedKeyText);
			X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
			PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return new SpeakEasyEccPublicKey(publicKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyEccPrivateKey readPrivateKey(String encodedKeyText) {
		try {
			byte[] encodedKeyBytes = stringEncoder.decodeBase64StringToBytes(encodedKeyText);
			PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKeyBytes);
			KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
			PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return new SpeakEasyEccPrivateKey(privateKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public StringEncoder getStringEncoder() {
		return stringEncoder;
	}
}
