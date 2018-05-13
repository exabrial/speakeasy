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

package com.github.exabrial.speakeasy.asymmetric.ecc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC_CURVE_NAME;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import com.github.exabrial.speakeasy.asymmetric.AsymmetricKeyUtils;
import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;

public class ECCKeyUtils implements AsymmetricKeyUtils<SpeakEasyEccPublicKey, SpeakEasyEccPrivateKey, SpeakEasyEccKeyPair> {
	private final StringEncoder stringEncoder;
	private final SecureRandomProvider secureRandomProvider;

	public ECCKeyUtils() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
	}

	public ECCKeyUtils(final StringEncoder stringEncoder, final SecureRandomProvider secureRandomProvider) {
		this.stringEncoder = stringEncoder;
		this.secureRandomProvider = secureRandomProvider;
	}

	@Override
	public SpeakEasyEccKeyPair createKeyPair() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC);
			final ECGenParameterSpec ecSpec = new ECGenParameterSpec(EC_CURVE_NAME);
			keyGen.initialize(ecSpec, secureRandomProvider.borrowSecureRandom());
			final KeyPair jceKeyPair = keyGen.generateKeyPair();
			final SpeakEasyEccKeyPair keyPair = new SpeakEasyEccKeyPair(jceKeyPair);
			return keyPair;
		} catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyEccPublicKey readPublicKey(final String encodedKeyText) {
		try {
			final byte[] encodedKeyBytes = stringEncoder.decodeStringToBytes(encodedKeyText);
			final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKeyBytes);
			final KeyFactory keyFactory = KeyFactory.getInstance(EC);
			final PublicKey publicKey = keyFactory.generatePublic(keySpec);
			return new SpeakEasyEccPublicKey(publicKey);
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public SpeakEasyEccPrivateKey readPrivateKey(final String encodedKeyText) {
		try {
			final byte[] encodedKeyBytes = stringEncoder.decodeStringToBytes(encodedKeyText);
			final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKeyBytes);
			final KeyFactory keyFactory = KeyFactory.getInstance(EC);
			final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
			return new SpeakEasyEccPrivateKey(privateKey);
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString(final SpeakEasyEccPublicKey speakEasyPublicKey) {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance(EC);
			final EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPublicKey.toKey(), X509EncodedKeySpec.class);
			return stringEncoder.encodeBytesAsString(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public String toString(final SpeakEasyEccPrivateKey speakEasyPrivateKey) {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance(EC);
			final EncodedKeySpec spec = keyFactory.getKeySpec(speakEasyPrivateKey.toKey(), PKCS8EncodedKeySpec.class);
			return stringEncoder.encodeBytesAsString(spec.getEncoded());
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
}
