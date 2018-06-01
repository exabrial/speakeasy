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

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class SymmetricKeyTest {

	@Test
	void testCheckKeyBytes_null() {
		final Executable executable = () -> {
			new TestSymmetricKey(null, 128);
		};
		assertThrows(NullPointerException.class, executable);
	}

	@Test
	void testCheckKeyBytes_tooSmall() {
		final Executable executable = () -> {
			new TestSymmetricKey(new byte[4], 128);
		};
		assertThrows(AssertionError.class, executable);
	}

	@Test
	void testCheckKeyBytes() {
		final byte[] keyBytes = new byte[16];
		Arrays.fill(keyBytes, (byte) 42);
		final TestSymmetricKey testSymmetricKey = new TestSymmetricKey(keyBytes, 128);
		assertTrue(Arrays.equals(keyBytes, testSymmetricKey.getKeyBytes()));
	}

	private class TestSymmetricKey extends SymmetricKey {
		TestSymmetricKey(final byte[] keyBytes, final int keyLength) {
			super(keyBytes, keyLength);
		}
	}
}
