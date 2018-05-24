package com.github.exabrial.speakeasy.asymmetric.rsa;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256_WITH_RSA;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.Signer;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class RSASigner implements Signer {
	private final SpeakEasyRSAPrivateKey privateKey;
	private final StringEncoder stringEncoder;
	private final SecureRandomProvider secureRandomProvider;

	public RSASigner(final SpeakEasyRSAPrivateKey privateKey) {
		this.privateKey = privateKey;
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
	}

	public RSASigner(final SpeakEasyRSAPrivateKey privateKey, final StringEncoder stringEncoder,
			final SecureRandomProvider secureRandomProvider) {
		this.privateKey = privateKey;
		this.stringEncoder = stringEncoder;
		this.secureRandomProvider = secureRandomProvider;
	}

	@Override
	public String signMessage(final String message) {
		try {
			final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			final Signature signature = Signature.getInstance(SHA256_WITH_RSA);
			final SecureRandom secureRandom = secureRandomProvider.borrowSecureRandom();
			signature.initSign(privateKey.toKey(), secureRandom);
			signature.update(messageBytes);
			final byte[] signatureBytes = signature.sign();
			return stringEncoder.encodeBytesAsString(signatureBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
