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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA512;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * SHA-512 implementation of Fingerprinter.
 */
public class SHA512Fingerprinter extends FingerprinterBase {
	private final StringEncoder stringEncoder;

	public SHA512Fingerprinter() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
	}

	public SHA512Fingerprinter(final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
	}

	@Override
	String getAlg() {
		return SHA512;
	}

	@Override
	StringEncoder getStringEncoder() {
		return stringEncoder;
	}
}
