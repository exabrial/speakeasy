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

package com.github.exabrial.speakeasy.oneway;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256;

import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * SHA-256 implementation of Fingerprinter.
 */
public class SHA256Fingerprinter extends FingerprinterBase {
	private final StringEncoder stringEncoder;

	public SHA256Fingerprinter(final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
	}

	@Override
	String getAlg() {
		return SHA256;
	}

	@Override
	StringEncoder getStringEncoder() {
		return stringEncoder;
	}
}