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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

public class Base64StringEncoderTest {
	private final Base64StringEncoder encoder = Base64StringEncoder.getSingleton();
	private final byte[] rfc4648TestVectorBytes = new byte[] { (byte) 0x14, (byte) 0xfb, (byte) 0x9c, (byte) 0x03, (byte) 0xd9,
			(byte) 0x7e };
	String rfc4648TestVectorString = "FPucA9l+";

	@Test
	public void testEncodeBytesAsString() {
		String encodeBytesAsString = encoder.encodeBytesAsString(rfc4648TestVectorBytes);
		assertEquals(rfc4648TestVectorString, encodeBytesAsString);
	}

	@Test
	public void testDecodeStringToBytes() {
		byte[] decodeStringToBytes = encoder.decodeStringToBytes(rfc4648TestVectorString);
		assertTrue(Arrays.equals(decodeStringToBytes, rfc4648TestVectorBytes));
	}
}
