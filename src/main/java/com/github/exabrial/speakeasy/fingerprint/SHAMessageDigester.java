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

package com.github.exabrial.speakeasy.fingerprint;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

class SHAMessageDigester implements MessageDigester {
	private final String digestName;

	public SHAMessageDigester(final String digestName) {
		this.digestName = digestName;
	}

	@Override
	public byte[] digest(final byte[] message) throws NoSuchAlgorithmException, NoSuchProviderException {
		return MessageDigest.getInstance(digestName, SUN).digest(message);
	}
}
