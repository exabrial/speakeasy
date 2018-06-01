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

package com.github.exabrial.speakeasy.oneway.keyed;

import org.bouncycastle.crypto.digests.Blake2bDigest;

import com.github.exabrial.speakeasy.comporator.BasicMessageComporator;
import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.Fingerprinter;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey;

/**
 * A keyed (HMAC like) Fingerprinter using the Blake2b function. The blake2b max
 * key length is 64 bytes, hence the limitation to this size.
 */
public class Blake2b256KeyedFingerprinter implements Fingerprinter {
	private final SymmetricKey symmetricKey;
	private final StringEncoder stringEncoder;
	private final MessageComporator messageComporator;

	public Blake2b256KeyedFingerprinter(final SymmetricKey symmetricKey) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.messageComporator = BasicMessageComporator.getSingleton();
	}

	@Override
	public String fingerprint(final String message) {
		final byte[] fingerprintBytes = digest(message);
		final String fingerprint = stringEncoder.encodeBytesAsString(fingerprintBytes);
		return fingerprint;
	}

	@Override
	public boolean verifyFingerprint(final String message, final String fingerprint) {
		final byte[] calculatedFingerprintBytes = digest(message);
		final byte[] presentedFingerprintBytes = stringEncoder.decodeStringToBytes(fingerprint);
		final boolean equals = messageComporator.compare(calculatedFingerprintBytes, presentedFingerprintBytes);
		return equals;
	}

	private byte[] digest(final String message) {
		final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
		final Blake2bDigest digest = new Blake2bDigest(symmetricKey.getKeyBytes(), 32, null, null);
		digest.update(messageBytes, 0, messageBytes.length);
		final byte[] fingerprintBytes = new byte[digest.getDigestSize()];
		digest.doFinal(fingerprintBytes, 0);
		return fingerprintBytes;
	}
}
