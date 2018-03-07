package com.github.exabrial.speakeasy.primitaves;

public interface SignatureVerifier {
	boolean verify(String payload, String signature);
}
