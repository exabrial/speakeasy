package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.GEN_ALG;

import java.security.Key;
import java.security.PrivateKey;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyPrivateKey;

public class SpeakEasyEccPrivateKey implements SpeakEasyPrivateKey {
	private final PrivateKey privateKey;

	public SpeakEasyEccPrivateKey(final PrivateKey privateKey) {
		if (!privateKey.getAlgorithm().equals(GEN_ALG)) {
			// TODO
			throw new RuntimeException("unsupportted alg");
		} else {
			this.privateKey = privateKey;
		}
	}

	@Override
	public byte[] getKeyBytes() {
		return privateKey.getEncoded();
	}

	@Override
	public Key toKey() {
		return privateKey;
	}
}
