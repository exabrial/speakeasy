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

package com.github.exabrial.speakeasy.asymmetric.ecc;

import java.security.KeyPair;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyKeyPair;

/**
 * An ECC key pair. @see SpeakEasyKeyPair
 */
public class SpeakEasyEccKeyPair implements SpeakEasyKeyPair {
	private final SpeakEasyEccPrivateKey privateKey;
	private final SpeakEasyEccPublicKey publicKey;

	public SpeakEasyEccKeyPair(final SpeakEasyEccPrivateKey privateKey, final SpeakEasyEccPublicKey publicKey) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
	}

	public SpeakEasyEccKeyPair(final KeyPair jceKeyPair) {
		this.privateKey = new SpeakEasyEccPrivateKey(jceKeyPair.getPrivate());
		this.publicKey = new SpeakEasyEccPublicKey(jceKeyPair.getPublic());
	}

	@Override
	public SpeakEasyEccPrivateKey getPrivateKey() {
		return privateKey;
	}

	@Override
	public SpeakEasyEccPublicKey getPublicKey() {
		return publicKey;
	}
}
