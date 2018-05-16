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

package com.github.exabrial.speakeasy.asymmetric;

/**
 * Parent interface for workging with asymmetric keys.
 * 
 * @param <Pub>
 *          public key type
 * @param <Priv>
 *          private key type
 * @param <Pair>
 *          key pair type
 */
public interface AsymmetricKeyUtils<Pub extends SpeakEasyPublicKey, Priv extends SpeakEasyPrivateKey, Pair extends SpeakEasyKeyPair> {
	Pair createKeyPair();

	Pub readPublicKey(String encodedKeyText);

	Priv readPrivateKey(String encodedKeyText);

	String toString(Pub speakEasyPublicKey);

	String toString(Priv speakEasyPrivateKey);
}
