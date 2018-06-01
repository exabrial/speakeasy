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

package com.github.exabrial.speakeasy.asymmetric.rsa;

import java.security.KeyPair;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyKeyPair;

/**
 * Holds a public and private RSA keypair.
 */
public class SpeakEasyRSAKeyPair implements SpeakEasyKeyPair {
	private final SpeakEasyRSAPrivateKey speakEasyRSAPrivateKey;
	private final SpeakEasyRSAPublicKey speakEasyRSAPublicKey;

	public SpeakEasyRSAKeyPair(final KeyPair jceKeyPair) {
		this.speakEasyRSAPrivateKey = new SpeakEasyRSAPrivateKey(jceKeyPair.getPrivate());
		this.speakEasyRSAPublicKey = new SpeakEasyRSAPublicKey(jceKeyPair.getPublic());
	}

	@Override
	public SpeakEasyRSAPrivateKey getPrivateKey() {
		return speakEasyRSAPrivateKey;
	}

	@Override
	public SpeakEasyRSAPublicKey getPublicKey() {
		return speakEasyRSAPublicKey;
	}
}
