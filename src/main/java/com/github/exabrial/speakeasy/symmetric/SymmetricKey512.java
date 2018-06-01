package com.github.exabrial.speakeasy.symmetric;

import org.bouncycastle.util.Arrays;

import com.github.exabrial.speakeasy.primitives.SpeakEasyKey;

/**
 * Represents a 512 bit [64 byte] key.
 */
public class SymmetricKey512 implements SpeakEasyKey {
	private static final int KEY_LENGTH = 64;
	private final byte[] keyBytes;

	SymmetricKey512(final byte[] keyBytes) {
		if (keyBytes == null) {
			throw new NullPointerException("Key cannot be null!");
		} else if (keyBytes.length != KEY_LENGTH) {
			throw new AssertionError("A " + KEY_LENGTH + " byte key must have " + KEY_LENGTH + " bytes....");
		} else {
			this.keyBytes = Arrays.copyOf(keyBytes, KEY_LENGTH);
		}
	}

	@Override
	public byte[] getKeyBytes() {
		return Arrays.copyOf(keyBytes, KEY_LENGTH);
	}
}
