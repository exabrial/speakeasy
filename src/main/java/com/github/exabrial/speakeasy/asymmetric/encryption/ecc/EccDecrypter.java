/**
 * 
 */
package com.github.exabrial.speakeasy.asymmetric.encryption.ecc;

import static com.github.exabrial.speakeasy.asymmetric.encryption.ecc.EccConstants.createCipher;
import static com.github.exabrial.speakeasy.primitaves.Base64StringEncoder.getSingleton;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.github.exabrial.speakeasy.asymmetric.encryption.ASymmetricDecrypter;
import com.github.exabrial.speakeasy.primitaves.StringEncoder;

/**
 * @author jonathanfisher
 *
 */
public class EccDecrypter implements ASymmetricDecrypter {
	private final StringEncoder stringEncoder;
	private final SpeakEasyEccPrivateKey privateKey;

	public EccDecrypter(final SpeakEasyEccPrivateKey privateKey) {
		this.stringEncoder = getSingleton();
		this.privateKey = privateKey;
	}

	public EccDecrypter(final StringEncoder stringEncoder, final SpeakEasyEccPrivateKey privateKey) {
		this.stringEncoder = stringEncoder;
		this.privateKey = privateKey;
	}

	@Override
	public String decrypt(String cipherText) {
		try {
			Cipher eccCipher = createCipher(privateKey);
			byte[] cipherTextBytes = stringEncoder.decodeBase64StringToBytes(cipherText);
			byte[] plainTextBytes = eccCipher.doFinal(cipherTextBytes);
			return stringEncoder.stringFromBytes(plainTextBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			throw new RuntimeException(e);
		}
	}

}
