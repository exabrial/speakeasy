package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.GEN_ALG;

import java.security.Key;
import java.security.PublicKey;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyPublicKey;

public class SpeakEasyEccPublicKey implements SpeakEasyPublicKey {
	public final PublicKey publicKey;

	public SpeakEasyEccPublicKey(final PublicKey publicKey) {
		if (!publicKey.getAlgorithm().equals(GEN_ALG)) {
			// TODO
			throw new RuntimeException("unsupportted alg");
		} else {
			this.publicKey = publicKey;
		}
	}

	@Override
	public byte[] getKeyBytes() {
		return publicKey.getEncoded();
	}

	@Override
	public Key toKey() {
		return publicKey;
	}
}
