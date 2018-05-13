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

import javax.xml.bind.DatatypeConverter;

public class HexStringEncoder implements StringEncoder {
	public static HexStringEncoder getSingleton() {
		return Singleton.Instance.encoder;
	}

	private enum Singleton {
		Instance;
		public final HexStringEncoder encoder;

		Singleton() {
			this.encoder = new HexStringEncoder();
		}
	}

	private HexStringEncoder() {
	}

	@Override
	public String encodeBytesAsString(final byte[] message) {
		return DatatypeConverter.printHexBinary(message);
	}

	@Override
	public byte[] decodeStringToBytes(final String message) {
		return DatatypeConverter.parseHexBinary(message);
	}
}
