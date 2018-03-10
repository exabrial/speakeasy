package com.github.exabrial.speakeasy.primitaves.signatures;

public interface Verifier {
	boolean verifymessageSignature(String message, String signature);
}
