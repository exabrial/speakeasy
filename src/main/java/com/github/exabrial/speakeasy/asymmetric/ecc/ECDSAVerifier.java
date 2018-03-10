package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC_SIG_ALG;
import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.primitaves.signatures.Verifier;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECDSAVerifier implements Verifier {
	private final SpeakEasyEccPublicKey publicKey;

	private final StringEncoder stringEncoder;

	public ECDSAVerifier(SpeakEasyEccPublicKey publicKey) {
		this.publicKey = publicKey;
		this.stringEncoder = getSingleton();
	}

	public ECDSAVerifier(SpeakEasyEccPublicKey publicKey, final StringEncoder stringEncoder) {
		this.publicKey = publicKey;
		this.stringEncoder = stringEncoder;
	}

	@Override
	public boolean verifymessageSignature(String message, String signatureText) {
		try {
			byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			byte[] signatureBytes = stringEncoder.decodeBase64StringToBytes(signatureText);
			Signature signature = Signature.getInstance(EC_SIG_ALG);
			signature.initVerify(publicKey.toKey());
			signature.update(messageBytes);
			return signature.verify(signatureBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
