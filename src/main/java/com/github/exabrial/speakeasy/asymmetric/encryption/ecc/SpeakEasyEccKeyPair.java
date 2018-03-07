package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import java.security.KeyPair;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyKeyPair;

public class SpeakEasyEccKeyPair implements SpeakEasyKeyPair {
	private final SpeakEasyEccPrivateKey privateKey;
	private final SpeakEasyEccPublicKey publicKey;

	public SpeakEasyEccKeyPair(SpeakEasyEccPrivateKey privateKey, SpeakEasyEccPublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	public SpeakEasyEccKeyPair(KeyPair jceKeyPair) {
		this.privateKey = new SpeakEasyEccPrivateKey(jceKeyPair.getPrivate());
		this.publicKey = new SpeakEasyEccPublicKey(jceKeyPair.getPublic());
	}

	@Override
	public SpeakEasyEccPrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public SpeakEasyEccPublicKey getPublicKey() {
		return publicKey;
	}
}
