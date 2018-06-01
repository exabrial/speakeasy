package com.github.exabrial.speakeasy.oneway.keyed;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import com.github.exabrial.speakeasy.symmetric.SymmetricKey512;

class Blake2b256KeyedFingerprinterTest {
	private final String testString = "I wanted to come up with a good construction joke... lets just say I'm working on it.";
	private final String expected = "IQCae1ZNGYrIq+mu65ScJVqxDa0ItVGt911xcD7sokc=";

	@Test
	void testFingerprintAndVerify() {
		final byte[] bytes = new byte[64];
		Arrays.fill(bytes, (byte) 1);
		final SymmetricKey512 key = new SymmetricKey512(bytes);
		final Blake2b256KeyedFingerprinter fingerPrinter = new Blake2b256KeyedFingerprinter(key);
		assertEquals(expected, fingerPrinter.fingerprint(testString));
	}

	@Test
	@Disabled
	void testVerifyFingerprint() {
		// TODO need some RFC test vectors
	}
}
