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

package com.github.exabrial.speakeasy.symmetric;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.Arrays;

import com.github.exabrial.speakeasy.primitives.SpeakEasyKey;

public abstract class SymmetricKey implements SpeakEasyKey {
	private final byte[] keyBytes;

	SymmetricKey(byte[] keyBytes, final int keyLength) {
		keyBytes = Arrays.copyOf(keyBytes, keyLength);
		checkKeyBytes(keyBytes, keyLength);
		this.keyBytes = keyBytes;
	}

	void checkKeyBytes(final byte[] keyBytes, final int keyLength) {
		if (keyBytes == null) {
			throw new NullPointerException("Key cannot be null!");
		} else if (keyBytes.length != keyLength) {
			throw new AssertionError("A " + keyLength + " byte key must have " + keyLength + " bytes....");
		}
	}

	@Override
	public byte[] getKeyBytes() {
		return Arrays.copyOf(keyBytes, keyBytes.length);
	}

	@Override
	public Key toJCEKey() {
		final SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, AES);
		return secretKey;
	}

	/**
	 * Transforms this key into a key usable by the JCE.
	 *
	 * @see javax.crypto.spec.SecretKeySpec#SecretKeySpec(byte[], int, int, String)
	 *
	 * @param algName
	 *          to use to use in the alg field of SecretKeySpec
	 * @return a SecretKeySpec of this key
	 */
	public Key toJCEKey(final String algName) {
		final SecretKey secretKey = new SecretKeySpec(keyBytes, 0, keyBytes.length, algName);
		return secretKey;
	}
}
