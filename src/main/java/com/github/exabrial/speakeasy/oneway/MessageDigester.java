package com.github.exabrial.speakeasy.oneway;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public interface MessageDigester {
	byte[] digest(byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException;
}
