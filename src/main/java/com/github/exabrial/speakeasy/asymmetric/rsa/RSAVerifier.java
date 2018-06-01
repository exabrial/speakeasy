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

import static com.github.exabrial.speakeasy.encoding.Base64StringEncoder.getSingleton;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256_WITH_RSA;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN_RSA_SIGN;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;

import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.primitives.Verifier;

/**
 * Verify a message using a private key. @see notes on RSASigner about
 * deterministic results.
 */
public class RSAVerifier implements Verifier {
	private final SpeakEasyRSAPublicKey publicKey;
	private final StringEncoder stringEncoder;

	public RSAVerifier(final SpeakEasyRSAPublicKey publicKey) {
		this.publicKey = publicKey;
		this.stringEncoder = getSingleton();
	}

	public RSAVerifier(final SpeakEasyRSAPublicKey publicKey, final StringEncoder stringEncoder) {
		this.publicKey = publicKey;
		this.stringEncoder = stringEncoder;
	}

	@Override
	public boolean verifyMessageSignature(final String message, final String signatureText) {
		try {
			final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			final byte[] signatureBytes = stringEncoder.decodeStringToBytes(signatureText);
			final Signature signature = Signature.getInstance(SHA256_WITH_RSA, SUN_RSA_SIGN);
			signature.initVerify(publicKey.toKey());
			signature.update(messageBytes);
			return signature.verify(signatureBytes);
		} catch (final NullPointerException | ArrayIndexOutOfBoundsException | SignatureException e) {
			return false;
		} catch (final InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
}
