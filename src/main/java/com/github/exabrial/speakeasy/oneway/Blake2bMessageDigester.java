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

package com.github.exabrial.speakeasy.oneway;

import org.bouncycastle.crypto.digests.Blake2bDigest;

class Blake2bMessageDigester implements MessageDigester {
	private final byte[] keyBytes;
	private final int outputLength;

	public Blake2bMessageDigester(final byte[] keyBytes, final int outputLength) {
		this.keyBytes = keyBytes;
		this.outputLength = outputLength;
	}

	@Override
	public byte[] digest(final byte[] messageBytes) {
		final Blake2bDigest digest = new Blake2bDigest(keyBytes, outputLength / 8, null, null);
		digest.update(messageBytes, 0, messageBytes.length);
		final byte[] fingerprintBytes = new byte[digest.getDigestSize()];
		digest.doFinal(fingerprintBytes, 0);
		return fingerprintBytes;
	}
}
