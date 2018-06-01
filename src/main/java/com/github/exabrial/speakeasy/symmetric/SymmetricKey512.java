package com.github.exabrial.speakeasy.symmetric;

/**
 * Represents a 512 bit [64 byte] key.
 */
public class SymmetricKey512 extends SymmetricKey {
	private static final int KEY_LENGTH = 64;

	SymmetricKey512(final byte[] keyBytes) {
		super(keyBytes, KEY_LENGTH);
	}
}
