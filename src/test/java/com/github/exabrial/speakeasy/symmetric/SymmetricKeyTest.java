package com.github.exabrial.speakeasy.symmetric;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class SymmetricKeyTest {

	@Test
	void testCheckKeyBytes_null() {
		final Executable executable = () -> {
			new TestSymmetricKey(null, 128);
		};
		assertThrows(NullPointerException.class, executable);
	}

	@Test
	void testCheckKeyBytes_tooSmall() {
		final Executable executable = () -> {
			new TestSymmetricKey(new byte[4], 128);
		};
		assertThrows(AssertionError.class, executable);
	}

	@Test
	void testCheckKeyBytes() {
		final byte[] keyBytes = new byte[16];
		Arrays.fill(keyBytes, (byte) 42);
		final TestSymmetricKey testSymmetricKey = new TestSymmetricKey(keyBytes, 128);
		assertTrue(Arrays.equals(keyBytes, testSymmetricKey.getKeyBytes()));
	}

	private class TestSymmetricKey extends SymmetricKey {
		TestSymmetricKey(final byte[] keyBytes, final int keyLength) {
			super(keyBytes, keyLength);
		}
	}
}
