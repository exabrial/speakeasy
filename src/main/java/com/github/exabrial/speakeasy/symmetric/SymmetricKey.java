package com.github.exabrial.speakeasy.symmetric;

import java.security.Key;

import javax.crypto.SecretKey;

import com.github.exabrial.speakeasy.primitives.keys.SpeakEasyKey;

public class SymmetricKey implements SpeakEasyKey {
	private final SecretKey secretKey;

	SymmetricKey(SecretKey secretKey) {
		this.secretKey = secretKey;
	}

	@Override
	public byte[] getKeyBytes() {
		return secretKey.getEncoded();
	}

	@Override
	public Key toKey() {
		return secretKey;
	}
}
