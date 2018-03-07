package com.github.exabrial.speakeasy.internal;

import static com.github.exabrial.speakeasy.internal.ECCConstants.SIG_ALG;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyPublicKey;
import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccPrivateKey;
import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccPublicKey;
import com.github.exabrial.speakeasy.primitives.keys.SpeakEasyKey;

public class SpeakEasySignature {
	private final Signature signature;

	public SpeakEasySignature(SpeakEasyKey speakEasyKey) {
		try {
			signature = Signature.getInstance(SIG_ALG);
			if (speakEasyKey instanceof SpeakEasyEccPrivateKey) {
				signature.initSign(((SpeakEasyEccPrivateKey) speakEasyKey).toKey(), SecureRandom.getInstanceStrong());
			} else if (speakEasyKey instanceof SpeakEasyPublicKey) {
				signature.initVerify(((SpeakEasyEccPublicKey) speakEasyKey).toKey());
			}
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public void update(byte[] payload) {
		try {
			signature.update(payload);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] sign() {
		try {
			return signature.sign();
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	public boolean verify(byte[] signatureBytes) {
		try {
			return signature.verify(signatureBytes);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
