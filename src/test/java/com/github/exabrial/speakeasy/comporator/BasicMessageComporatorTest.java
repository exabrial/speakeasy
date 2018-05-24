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

package com.github.exabrial.speakeasy.comporator;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

class BasicMessageComporatorTest {
	private final BasicMessageComporator comporator = BasicMessageComporator.getSingleton();

	@Test
	void testCompare() {
		assertTrue(comporator.compare("calculatedFingerprint".getBytes(), "calculatedFingerprint".getBytes()));
	}

	@Test
	void testCompare_notTheSame() {
		assertFalse(comporator.compare("calculatedFingerprint".getBytes(), "calculatedFingerprint2".getBytes()));
	}

	@Test
	void testCompare_null() {
		Executable executable = () -> {
			comporator.compare(null, "calculatedFingerprint2".getBytes());
		};
		assertThrows(NullPointerException.class, executable);
	}

	@Test
	void testCompare_null2() {
		Executable executable = () -> {
			comporator.compare("calculatedFingerprint".getBytes(), null);
		};
		assertThrows(NullPointerException.class, executable);
	}
}
