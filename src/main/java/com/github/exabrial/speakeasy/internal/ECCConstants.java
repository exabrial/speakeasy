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

	//
	// protected static String toString(Key key) {
	// try {
	// KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
	// Class<? extends EncodedKeySpec> keySpecClass;
	// if (key instanceof PublicKey) {
	// keySpecClass = X509EncodedKeySpec.class;
	// } else if (key instanceof PrivateKey) {
	// keySpecClass = PKCS8EncodedKeySpec.class;
	// } else {
	// throw new RuntimeException("Key type not supported");
	// }
	// EncodedKeySpec spec = keyFactory.getKeySpec(key, keySpecClass);
	// return new String(Base64.getEncoder().encode(spec.getEncoded()), UTF_8);
	// } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
	// throw new RuntimeException(e);
	// }
	//
	// try {
	// secureRandom = SecureRandom.getInstanceStrong();
	// byte[] keyBytes =
	// Base64.getDecoder().decode(encodedPrivateKey.getBytes(UTF_8));
	// PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
	// KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
	// privateKey = keyFactory.generatePrivate(keySpec);
	// } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
	// throw new RuntimeException(e);
	// }
	//
	// try {
	// X509EncodedKeySpec keySpec = new X509EncodedKeySpec(
	// Base64.getDecoder().decode(encodedPublicKey.getBytes(UTF_8)));
	// KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
	// publicKey = keyFactory.generatePublic(keySpec);
	// } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
	// throw new RuntimeException(e);
	// }
	// }
}
