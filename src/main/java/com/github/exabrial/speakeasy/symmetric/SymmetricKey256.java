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
 * Represents a 256 bit [32 byte] key.
 */
public class SymmetricKey256 extends SymmetricKey {
	private static final int KEY_LENGTH = 256;

	public SymmetricKey256(final byte[] keyBytes) {
		super(keyBytes, KEY_LENGTH);
	}
}
