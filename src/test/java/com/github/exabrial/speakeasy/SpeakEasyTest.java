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

package com.github.exabrial.speakeasy;

import org.junit.Rule;
import org.junit.Test;
import org.junit.contrib.java.lang.system.RestoreSystemProperties;
import org.junit.rules.TestRule;

import com.github.exabrial.speakeasy.internal.WhatInTheHellAreYouThinkingException;

public class SpeakEasyTest {
	@Rule
	public TestRule restoreSystemProperties = new RestoreSystemProperties();

	@Test(expected = WhatInTheHellAreYouThinkingException.class)
	public void testBasicJdkCheck() {
		System.setProperty("java.version", "1.8.0_41-b10");
		SpeakEasy.addSunEc();
	}

	@Test(expected = WhatInTheHellAreYouThinkingException.class)
	public void testBasicJdkCheck2() {
		System.setProperty("java.version", "1.8.0_42");
		SpeakEasy.addSunEc();
	}

	@Test
	public void testBasicJdkCheck_ok() {
		System.setProperty("java.version", "1.8.0_162");
		SpeakEasy.addSunEc();
	}

	@Test
	public void testBasicJdkCheck_ok2() {
		System.setProperty("java.version", "1.8.0_162-b10");
		SpeakEasy.addSunEc();
	}

	@Test
	public void testBasicJdkCheck_ok3() {
		System.setProperty("java.version", "9.0.4");
		SpeakEasy.addSunEc();
	}
}
