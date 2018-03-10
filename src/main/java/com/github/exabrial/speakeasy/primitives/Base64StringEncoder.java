package com.github.exabrial.speakeasy.primitives;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Base64StringEncoder implements StringEncoder {

	public static Base64StringEncoder getSingleton() {
		return Singleton.Instance.encoder;
	}

	private static enum Singleton {
		Instance;
		public final Base64StringEncoder encoder;

		Singleton() {
			this.encoder = new Base64StringEncoder();
		}
	}

	private Base64StringEncoder() {
	}

	@Override
	public String encodeBytesAsBase64(byte[] message) {
		return Base64.getEncoder().encodeToString(message);
	}

	@Override
	public byte[] decodeBase64StringToBytes(String message) {
		return Base64.getDecoder().decode(message);
	}

	@Override
	public byte[] getStringAsBytes(String message) {
		return message.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public String stringFromBytes(byte[] message) {
		return new String(message, StandardCharsets.UTF_8);
	}

}
