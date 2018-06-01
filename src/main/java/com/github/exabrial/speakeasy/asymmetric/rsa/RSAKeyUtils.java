/**
 * Copyright [2018] [Jonathan S. Fisher]
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.github.exabrial.speakeasy.asymmetric.rsa;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.RSA;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.RSA_EXPONENT;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.RSA_KEY_LENGTH;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN_RSA_SIGN;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import com.github.exabrial.speakeasy.asymmetric.AsymmetricKeyUtils;
import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Utility class for managing RSA keys. @see
 * com.github.exabrial.speakeasy.symmetric.SymmetricKeyUtils.generateSecureSymmetricKey()
 * for some notes on secure generation.
 */
public class RSAKeyUtils implements AsymmetricKeyUtils<SpeakEasyRSAPublicKey, SpeakEasyRSAPrivateKey, SpeakEasyRSAKeyPair> {
	private final StringEncoder stringEncoder;
	private final SecureRandomProvider secureRandomProvider;

	public RSAKeyUtils() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
	}

	public RSAKeyUtils(final StringEncoder stringEncoder, final SecureRandomProvider secureRandomProvider) {
		this.stringEncoder = stringEncoder;
		this.secureRandomProvider = secureRandomProvider;
	}

	@Override
	public SpeakEasyRSAKeyPair createKeyPair() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(RSA, SUN_RSA_SIGN);
			final RSAKeyGenParameterSpec ecSpec = new RSAKeyGenParameterSpec(RSA_KEY_LENGTH, RSA_EXPONENT);
			keyGen.initialize(ecSpec, secureRandomProvider.borrowSecureRandom());
			final KeyPair jceKeyPair = keyGen.generateKeyPair();
			final SpeakEasyRSAKeyPair keyPair = new SpeakEasyRSAKeyPair(jceKeyPair);
			return keyPair;
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyRSAPublicKey readPublicKey(final String encodedKeyText) {
		try {
			final byte[] encodedKeyBytes = stringEncoder.decodeStringToBytes(encodedKeyText);
			final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKeyBytes);
			final KeyFactory keyFactory = KeyFactory.getInstance(RSA, SUN_RSA_SIGN);
			final PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return new SpeakEasyRSAPublicKey(publicKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyRSAPrivateKey readPrivateKey(final String encodedKeyText) {
		try {
			final byte[] encodedKeyBytes = stringEncoder.decodeStringToBytes(encodedKeyText);
			final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKeyBytes);
			final KeyFactory keyFactory = KeyFactory.getInstance(RSA, SUN_RSA_SIGN);
			final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return new SpeakEasyRSAPrivateKey(privateKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString(final SpeakEasyRSAPublicKey speakEasyPublicKey) {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance(RSA, SUN_RSA_SIGN);
			final EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPublicKey.toJCEKey(), X509EncodedKeySpec.class);
			return stringEncoder.encodeBytesAsString(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString(final SpeakEasyRSAPrivateKey speakEasyPrivateKey) {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance(RSA, SUN_RSA_SIGN);
			final EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPrivateKey.toJCEKey(), PKCS8EncodedKeySpec.class);
			return stringEncoder.encodeBytesAsString(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
}
