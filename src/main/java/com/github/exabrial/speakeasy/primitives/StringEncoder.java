package com.github.exabrial.speakeasy.primitives;

public interface StringEncoder {
	String encodeBytesAsBase64(byte[] message);

	byte[] decodeBase64StringToBytes(String message);

	byte[] getStringAsBytes(String message);

	String stringFromBytes(byte[] message);
}
