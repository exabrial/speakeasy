package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import com.github.exabrial.speakeasy.internal.SpeakEasySignature;
import com.github.exabrial.speakeasy.primitaves.signatures.Verifier;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECDSAVerifier implements Verifier {
	private final SpeakEasyEccPublicKey publicKey;

	private final StringEncoder stringEncoder;

	public ECDSAVerifier(SpeakEasyEccPublicKey publicKey) {
		this.publicKey = publicKey;
		this.stringEncoder = getSingleton();
	}

	public ECDSAVerifier(final StringEncoder stringEncoder, SpeakEasyEccPublicKey publicKey) {
		this.publicKey = publicKey;
		this.stringEncoder = stringEncoder;
	}

	@Override
	public boolean verifyPayloadSignature(String payload, String signatureText) {
		byte[] payloadBytes = stringEncoder.getStringAsBytes(payload);
		byte[] signatureBytes = stringEncoder.decodeBase64StringToBytes(signatureText);
		SpeakEasySignature signature = new SpeakEasySignature(publicKey);
		signature.update(payloadBytes);
		return signature.verify(signatureBytes);
	}
}
