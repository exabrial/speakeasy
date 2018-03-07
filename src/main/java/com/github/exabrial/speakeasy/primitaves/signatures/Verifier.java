package com.github.exabrial.speakeasy.primitaves.signatures;

public interface Verifier {
	boolean verifyPayloadSignature(String payload, String signature);
}
