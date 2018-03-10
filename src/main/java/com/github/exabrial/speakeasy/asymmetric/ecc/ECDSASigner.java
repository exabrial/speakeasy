package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC_SIG_ALG;
import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.primitaves.signatures.Signer;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECDSASigner implements Signer {
	private final SpeakEasyEccPrivateKey privateKey;
	private final StringEncoder stringEncoder;

	public ECDSASigner(SpeakEasyEccPrivateKey privateKey) {
		this.privateKey = privateKey;
		this.stringEncoder = getSingleton();
	}

	public ECDSASigner(SpeakEasyEccPrivateKey privateKey, final StringEncoder stringEncoder) {
		this.privateKey = privateKey;
		this.stringEncoder = stringEncoder;
	}

	@Override
	public String signmessage(String message) {
		try {
			byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			Signature signature = Signature.getInstance(EC_SIG_ALG);
			SecureRandom secureRandom = SecureRandom.getInstanceStrong();
			signature.initSign(privateKey.toKey(), secureRandom);
			signature.update(messageBytes);
			byte[] signatureBytes = signature.sign();
			return stringEncoder.encodeBytesAsBase64(signatureBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
