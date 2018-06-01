package com.github.exabrial.speakeasy.oneway;

import org.bouncycastle.crypto.digests.Blake2bDigest;

public class Blake2bMessageDigester implements MessageDigester {
	private final byte[] keyBytes;
	private final int outputLength;

	public Blake2bMessageDigester(byte[] keyBytes, int outputLength) {
		this.keyBytes = keyBytes;
		this.outputLength = outputLength;
	}

	@Override
	public byte[] digest(byte[] messageBytes) {
		final Blake2bDigest digest = new Blake2bDigest(keyBytes, outputLength / 8, null, null);
		digest.update(messageBytes, 0, messageBytes.length);
		final byte[] fingerprintBytes = new byte[digest.getDigestSize()];
		digest.doFinal(fingerprintBytes, 0);
		return fingerprintBytes;
	}
}
