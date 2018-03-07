package com.github.exabrial.speakeasy.primitaves;

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
	public String encodeBytesAsBase64(byte[] payload) {
		return Base64.getEncoder().encodeToString(payload);
	}

	@Override
	public byte[] decodeBase64StringToBytes(String payload) {
		return Base64.getDecoder().decode(payload);
	}

	@Override
	public byte[] getStringAsBytes(String payload) {
		return payload.getBytes(StandardCharsets.UTF_8);
	}

	@Override
	public String stringFromBytes(byte[] payload) {
		return new String(payload, StandardCharsets.UTF_8);
	}

}
