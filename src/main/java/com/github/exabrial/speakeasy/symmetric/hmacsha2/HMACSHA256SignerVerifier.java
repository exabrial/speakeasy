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

package com.github.exabrial.speakeasy.symmetric.hmacsha2;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.HMAC_SHA256;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.misc.ConstantTimeMessageComporator;
import com.github.exabrial.speakeasy.primitives.Fingerprinter;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey;

public class HMACSHA256SignerVerifier implements Fingerprinter {
	private final SymmetricKey symmetricKey;
	private final StringEncoder stringEncoder;
	private final MessageComporator messageComporator;

	public HMACSHA256SignerVerifier(final SymmetricKey symmetricKey) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.messageComporator = ConstantTimeMessageComporator.getSingleton();
	}

	public HMACSHA256SignerVerifier(final SymmetricKey symmetricKey, final StringEncoder stringEncoder) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = stringEncoder;
		this.messageComporator = ConstantTimeMessageComporator.getSingleton();
	}

	public HMACSHA256SignerVerifier(final SymmetricKey symmetricKey, final StringEncoder stringEncoder,
			final MessageComporator messageComporator) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = stringEncoder;
		this.messageComporator = messageComporator;
	}

	@Override
	public String fingerprint(final String message) {
		try {
			final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			final Mac hmac = Mac.getInstance(HMAC_SHA256);
			final SecretKeySpec secret_key = new SecretKeySpec(symmetricKey.getKeyBytes(), HMAC_SHA256);
			hmac.init(secret_key);
			final byte[] signatureBytes = hmac.doFinal(messageBytes);
			final String signature = stringEncoder.encodeBytesAsString(signatureBytes);
			return signature;
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean verifyFingerprint(final String message, final String signature) {
		try {
			final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
			final Mac hmac = Mac.getInstance(HMAC_SHA256);
			final SecretKeySpec secret_key = new SecretKeySpec(symmetricKey.getKeyBytes(), HMAC_SHA256);
			hmac.init(secret_key);
			final byte[] cSignatureBytes = hmac.doFinal(messageBytes);
			final String cSignature = stringEncoder.encodeBytesAsString(cSignatureBytes);
			return messageComporator.compare(cSignature, signature);
		} catch (final InvalidKeyException | NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}
