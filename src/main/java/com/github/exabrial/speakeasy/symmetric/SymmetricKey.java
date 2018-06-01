package com.github.exabrial.speakeasy.symmetric;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import com.github.exabrial.speakeasy.primitives.SpeakEasyKey;

public abstract class SymmetricKey implements SpeakEasyKey {
	private final byte[] keyBytes;

	SymmetricKey(byte[] keyBytes, final int keyLength) {
		keyBytes = Arrays.copyOf(keyBytes, keyLength);
		checkKeyBytes(keyBytes, keyLength);
		this.keyBytes = keyBytes;
	}

	void checkKeyBytes(final byte[] keyBytes, final int keyLength) {
		if (keyBytes == null) {
			throw new NullPointerException("Key cannot be null!");
		} else if (keyBytes.length != keyLength) {
			throw new AssertionError("A " + keyLength + " byte key must have " + keyLength + " bytes....");
		}
	}

	@Override
	public byte[] getKeyBytes() {
		return Arrays.copyOf(keyBytes, keyBytes.length);
	}

	@Override
	public Key toJCEKey() {
		final SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, "SpeakEasy");
		return secretKey;
	}

	public int getKeyLength() {
		return keyBytes.length;
	}
}
