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
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.AES_KEY_SIZE;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN_JCE;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.entropy.NativeThreadLocalSecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Utilities for working with SymmetricKey objects.
 */
public class SymmetricKeyUtils {
	private final StringEncoder stringEncoder;
	private final SecureRandomProvider secureRandomProvider;

	public SymmetricKeyUtils() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.secureRandomProvider = NativeThreadLocalSecureRandomProvider.getSingleton();
	}

	public SymmetricKeyUtils(final StringEncoder stringEncoder, final SecureRandomProvider secureRandomProvider) {
		this.stringEncoder = stringEncoder;
		this.secureRandomProvider = secureRandomProvider;
	}

	/**
	 * Create a string representation of a key that can be deserialized later.
	 *
	 * @param symmetricKey
	 *          the key to be serialized
	 * @return the string representation of the key
	 */
	public String toString(final SymmetricKey symmetricKey) {
		final byte[] keyBytes = symmetricKey.toKey().getEncoded();
		final String encodedKey = stringEncoder.encodeBytesAsString(keyBytes);
		return encodedKey;
	}

	/**
	 * Create a object representation of key from the serialized string.
	 *
	 * @param encodedKeyString
	 *          string representation of a key
	 * @return the object represented by the string
	 */
	public SymmetricKey fromString(final String encodedKeyString) {
		final byte[] encodedKeyBytes = stringEncoder.decodeStringToBytes(encodedKeyString);
		final SecretKey secretKey = new SecretKeySpec(encodedKeyBytes, 0, encodedKeyBytes.length, AES);
		final SymmetricKey symmetricKey = new SymmetricKey(secretKey);
		return symmetricKey;
	}

	/**
	 * The best way to create a new key is to generate it here. A lot of people with
	 * take a random string and called .getBytes(), which only returns bytes
	 * possible in ascii or UTF charsets, severely limiting the entropy of the key.
	 * The method ensure correctness.
	 *
	 * @return a randomly generated key
	 */
	public SymmetricKey generateSecureSymmetricKey() {
		try {
			final KeyGenerator keyGen = KeyGenerator.getInstance(AES, SUN_JCE);
			keyGen.init(AES_KEY_SIZE, secureRandomProvider.borrowSecureRandom());
			final SecretKey secretKey = keyGen.generateKey();
			return new SymmetricKey(secretKey);
		} catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
}
