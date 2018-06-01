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

/**
 * An algorithm that uses a single key for two converse or inverse operations is
 * called symmetric. This class holds a 128 bit value key value.
 */
public class SymmetricKey128 extends SymmetricKey {
	private static final int KEY_LENGTH = 16;

	SymmetricKey128(final byte[] keyBytes) {
		super(keyBytes, KEY_LENGTH);
	}
}
