package com.github.exabrial.speakeasy.internal;

import static com.github.exabrial.speakeasy.internal.ECCConstants.FIXED_IV;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.spec.IESParameterSpec;

import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccPrivateKey;
import com.github.exabrial.speakeasy.asymmetric.ecc.SpeakEasyEccPublicKey;
import com.github.exabrial.speakeasy.primitives.keys.SpeakEasyKey;

public class SpeakEasyCipher {
	private final IESCipher cipher;

	public SpeakEasyCipher(SpeakEasyKey speakEasyKey) {
		try {
			IESEngine engine = new IESEngine(new ECDHBasicAgreement(), new KDF2BytesGenerator(new SHA256Digest()),
					new HMac(new SHA256Digest()), new GCMBufferedBlockCipher(new AESEngine()));
			cipher = new IESCipher(engine);
			IESParameterSpec parameterSpec = new IESParameterSpec(null, null, 256, 128, FIXED_IV);
			if (speakEasyKey instanceof SpeakEasyEccPublicKey) {
				cipher.engineInit(Cipher.ENCRYPT_MODE, speakEasyKey.toKey(), parameterSpec, new SecureRandom());
			} else if (speakEasyKey instanceof SpeakEasyEccPrivateKey) {
				cipher.engineInit(Cipher.DECRYPT_MODE, speakEasyKey.toKey(), parameterSpec, new SecureRandom());
			} else {
				throw new RuntimeException("key not supported");
			}
		} catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	public byte[] doFinal(byte[] payload) {
		try {
			return cipher.engineDoFinal(payload, 0, payload.length);
		} catch (IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}
}
