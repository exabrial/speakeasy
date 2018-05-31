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

import java.util.Locale;

import javax.xml.bind.DatatypeConverter;

import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Serializes and deserializes a byte[] using standard 2-digit hexadecimal
 * encoding.
 */
public class HexStringEncoder implements StringEncoder {
	private HexStringEncoder() {
	}

	public static HexStringEncoder getSingleton() {
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
			encodedString = DatatypeConverter.printHexBinary(message).toUpperCase(Locale.US);
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
			decodedBytes = DatatypeConverter.parseHexBinary(message);
		}
		return decodedBytes;
	}

	private enum Singleton {
		Instance;
		public final HexStringEncoder encoder;

		Singleton() {
			this.encoder = new HexStringEncoder();
		}
	}
}
