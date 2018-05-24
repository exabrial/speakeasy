package com.github.exabrial.speakeasy;

import com.github.exabrial.speakeasy.encoding.HexStringEncoder;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class StringBytesEncoder implements StringEncoder {
	@Override
	public String encodeBytesAsString(byte[] message) {
		return HexStringEncoder.getSingleton().encodeBytesAsString(message);
	}

	@Override
	public byte[] decodeStringToBytes(String message) {
		return message.getBytes();
	}
}
