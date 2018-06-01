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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256_WITH_RSA;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN_RSA_SIGN;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.Signer;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Signs data using the RSA signature scheme.
 */
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
			final Signature signature = Signature.getInstance(SHA256_WITH_RSA, SUN_RSA_SIGN);
			final SecureRandom secureRandom = secureRandomProvider.borrowSecureRandom();
			signature.initSign(privateKey.toJCEKey(), secureRandom);
			signature.update(messageBytes);
			final byte[] signatureBytes = signature.sign();
			return stringEncoder.encodeBytesAsString(signatureBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
}
