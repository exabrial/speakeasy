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

package com.github.exabrial.speakeasy.encoding;

import java.util.Base64;

import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Serializes and deserializes a byte[] using rfc compliant base64 encoding.
 * This implementation does not escape URL characters.
 */
public class Base64StringEncoder implements StringEncoder {
	private Base64StringEncoder() {
	}

	public static Base64StringEncoder getSingleton() {
		return Singleton.Instance.encoder;
	}

	@Override
	public String encodeBytesAsString(final byte[] message) {
		final String encodedString;
		if (message == null) {
			encodedString = null;
		} else if (message.length == 0) {
			encodedString = "";
		} else {
			encodedString = Base64.getEncoder().encodeToString(message);
		}
		return encodedString;
	}

	@Override
	public byte[] decodeStringToBytes(final String message) {
		final byte[] decodedBytes;
		if (message == null) {
			decodedBytes = null;
		} else if (message.length() == 0) {
			decodedBytes = new byte[0];
		} else {
			decodedBytes = Base64.getDecoder().decode(message);
		}
		return decodedBytes;
	}

	private enum Singleton {
		Instance;
		Base64StringEncoder encoder;

		Singleton() {
			this.encoder = new Base64StringEncoder();
		}
	}
}
