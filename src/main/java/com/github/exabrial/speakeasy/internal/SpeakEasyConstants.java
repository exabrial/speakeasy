package com.github.exabrial.speakeasy.internal;

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class SpeakEasyConstants {
	public static final String AES_GCM = "AES/GCM/PKCS5Padding";
	public static final int GCM_NONCE_LENGTH = 12;
	public static final int AES_GCM_TAG_LENGTH = 128;
	public static final String EC = "EC";
	public static final String EC_SIG_ALG = "SHA256withECDSA";
	public static final String EC_CURVE_NAME = "secp256r1";
	static {
		if (Arrays.asList(Security.getProviders()).stream()
				.filter(provider -> provider.getName().equals(BouncyCastleProvider.PROVIDER_NAME)).findFirst()
				.orElse(null) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	private SpeakEasyConstants() {
	}
}
