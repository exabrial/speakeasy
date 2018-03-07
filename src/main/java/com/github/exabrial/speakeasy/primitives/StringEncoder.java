package com.github.exabrial.speakeasy.primitives;

public interface StringEncoder {
	String encodeBytesAsBase64(byte[] payload);

	byte[] decodeBase64StringToBytes(String payload);

	byte[] getStringAsBytes(String payload);

	String stringFromBytes(byte[] payload);
}
