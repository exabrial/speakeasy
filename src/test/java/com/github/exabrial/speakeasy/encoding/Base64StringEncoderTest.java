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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;

public class Base64StringEncoderTest {
	private final Base64StringEncoder encoder = Base64StringEncoder.getSingleton();
	private final byte[] rfc4648TestVectorBytes = new byte[] { (byte) 0x14, (byte) 0xfb, (byte) 0x9c, (byte) 0x03, (byte) 0xd9,
			(byte) 0x7e };
	String rfc4648TestVectorString = "FPucA9l+";

	@Test
	public void testEncodeBytesAsString() {
		final String encodeBytesAsString = encoder.encodeBytesAsString(rfc4648TestVectorBytes);
		assertEquals(rfc4648TestVectorString, encodeBytesAsString);
	}

	@Test
	public void testDecodeStringToBytes() {
		final byte[] decodeStringToBytes = encoder.decodeStringToBytes(rfc4648TestVectorString);
		assertTrue(Arrays.equals(decodeStringToBytes, rfc4648TestVectorBytes));
	}

	@Test
	public void testEncodeNull() {
		assertNull(encoder.encodeBytesAsString(null));
	}

	@Test
	public void testDecodeNull() {
		assertNull(encoder.decodeStringToBytes(null));
	}

	@Test
	public void testEncode0Length() {
		assertEquals("", encoder.encodeBytesAsString(new byte[0]));
	}

	@Test
	public void testDecode0Length() {
		assertTrue(Arrays.equals(new byte[0], encoder.decodeStringToBytes("")));
	}
}
