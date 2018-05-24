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

package com.github.exabrial.testing;

import com.github.exabrial.speakeasy.encoding.HexStringEncoder;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public class StringBytesEncoder implements StringEncoder {
	@Override
	public String encodeBytesAsString(byte[] message) {
		return HexStringEncoder.getSingleton().encodeBytesAsString(message);
	}

	@Override
	public byte[] decodeStringToBytes(String message) {
		return message.getBytes();
	}
}
