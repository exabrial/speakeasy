package com.github.exabrial.speakeasy.internal;

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class ECCConstants {
	public static final String GEN_ALG = "EC";
	public static final String SIG_ALG = "SHA256withECDSA";
	public static final String EC_CURVE_NAME = "secp256r1";
	static final byte[] FIXED_IV;

	static {
		if (Arrays.asList(Security.getProviders()).stream()
				.filter(provider -> provider.getName().equals(BouncyCastleProvider.PROVIDER_NAME)).findFirst()
				.orElse(null) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
		FIXED_IV = new byte[16];
		Arrays.fill(FIXED_IV, (byte) 0);
	}

	private ECCConstants() {
	}
}
