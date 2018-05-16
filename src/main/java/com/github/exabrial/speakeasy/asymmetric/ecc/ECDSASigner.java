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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC_SIG_ALG;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.Signer;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class ECDSASigner implements Signer {
	private final SpeakEasyEccPrivateKey privateKey;
	private final StringEncoder stringEncoder;
	private final SecureRandomProvider secureRandomProvider;

	public ECDSASigner(final SpeakEasyEccPrivateKey privateKey) {
		this.privateKey = privateKey;
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
	}

	public ECDSASigner(final SpeakEasyEccPrivateKey privateKey, final StringEncoder stringEncoder,
			final SecureRandomProvider secureRandomProvider) {
		this.privateKey = privateKey;
		this.stringEncoder = stringEncoder;
		this.secureRandomProvider = secureRandomProvider;
	}

	@Override
	public String signMessage(final String message) {
		try {
			final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			final Signature signature = Signature.getInstance(EC_SIG_ALG);
			final SecureRandom secureRandom = secureRandomProvider.borrowSecureRandom();
			signature.initSign(privateKey.toKey(), secureRandom);
			signature.update(messageBytes);
			final byte[] signatureBytes = signature.sign();
			return stringEncoder.encodeBytesAsString(signatureBytes);
		} catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
}
