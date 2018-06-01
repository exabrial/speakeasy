package com.github.exabrial.speakeasy.oneway;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHAMessageDigester implements MessageDigester {
	private final String digestName;

	public SHAMessageDigester(String digestName) {
		this.digestName = digestName;
	}

	@Override
	public byte[] digest(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException {
		return MessageDigest.getInstance(digestName, SUN).digest(message);
	}
}
