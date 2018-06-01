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

import java.lang.reflect.InvocationTargetException;

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
		final byte[] keyBytes = symmetricKey.getKeyBytes();
		final String encodedKey = stringEncoder.encodeBytesAsString(keyBytes);
		return encodedKey;
	}

	/**
	 * Create a object representation of key from the serialized string.
	 *
	 * @param encodedKeyString
	 *          string representation of a key
	 * @return the object represented by the string
	 * @throws UnknownKeyLengthException
	 *           if the keyLength isn't supported
	 */
	public <K extends SymmetricKey> K fromString(final String encodedKeyString, final Class<K> keyClazz)
			throws UnknownKeyLengthException {
		final byte[] keyBytes = stringEncoder.decodeStringToBytes(encodedKeyString);
		final K symmetricKey;
		try {
			symmetricKey = keyClazz.getDeclaredConstructor(byte[].class).newInstance(keyBytes);
		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
		return symmetricKey;
	}

	/**
	 * The best way to create a new key is to generate it here. A lot of people with
	 * take a random string and call .getBytes(), which only returns bytes possible
	 * in ascii or UTF charsets, severely limiting the entropy of the key. The
	 * method ensure correctness by allowing for all combinations possible.
	 *
	 * @return a randomly generated key
	 */
	public <K extends SymmetricKey> K generateSecureSymmetricKey(final Class<K> keyClazz) {
		final byte[] keyBytes = new byte[64];
		secureRandomProvider.borrowSecureRandom().nextBytes(keyBytes);
		final K symmetricKey;
		try {
			symmetricKey = keyClazz.getDeclaredConstructor(byte[].class).newInstance(keyBytes);
		} catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException
				| NoSuchMethodException | SecurityException e) {
			throw new RuntimeException(e);
		}
		return symmetricKey;
	}
}
