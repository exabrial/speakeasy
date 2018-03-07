package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.primitives.Base64StringEncoder.getSingleton;

import com.github.exabrial.speakeasy.internal.SpeakEasySignature;
import com.github.exabrial.speakeasy.primitaves.signatures.Signer;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECDSASigner implements Signer {
	private final SpeakEasyEccPrivateKey privateKey;
	private final StringEncoder stringEncoder;

	public ECDSASigner(SpeakEasyEccPrivateKey privateKey) {
		this.privateKey = privateKey;
		this.stringEncoder = getSingleton();
	}

	public ECDSASigner(final StringEncoder stringEncoder, SpeakEasyEccPrivateKey privateKey) {
		this.privateKey = privateKey;
		this.stringEncoder = stringEncoder;
	}

	@Override
	public String signPayload(String payload) {
		byte[] payloadBytes = stringEncoder.getStringAsBytes(payload);
		SpeakEasySignature signature = new SpeakEasySignature(privateKey);
		signature.update(payloadBytes);
		byte[] signatureBytes = signature.sign();
		return stringEncoder.encodeBytesAsBase64(signatureBytes);
	}
}
