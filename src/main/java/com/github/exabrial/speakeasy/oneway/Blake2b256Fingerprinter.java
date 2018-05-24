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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.BC_PROVIDER;
import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.BLAKE2B_256;

import java.security.Provider;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Blake2b is _the fastest_ cryptographic hash algorithm available, it's much
 * faster than md5 and sha1, but offers none of the security problems. This
 * implementation uses a "self-keying" construction.
 */
public class Blake2b256Fingerprinter extends FingerprinterBase {
	private final StringEncoder stringEncoder;

	public Blake2b256Fingerprinter() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
	}

	public Blake2b256Fingerprinter(final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
	}

	@Override
	String getAlg() {
		return BLAKE2B_256;
	}

	@Override
	StringEncoder getStringEncoder() {
		return stringEncoder;
	}

	@Override
	Provider getProvider() {
		return BC_PROVIDER;
	}
}
