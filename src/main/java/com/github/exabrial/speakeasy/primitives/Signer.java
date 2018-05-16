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

package com.github.exabrial.speakeasy.primitives;

/**
 * Produces an output for a given arbitrarily-sized input that can be
 * deterministically checked by a verifier. The output necessarily is not
 * consistent for the same input, however, the corresponding verifier must
 * always return true for a signature created by a corresponding signer. Usually
 * signers can be considered to be keyed Fingerprint functions.
 */
public interface Signer {
	/**
	 * Produce a signature for a plaintext message input.
	 * 
	 * @param message
	 *          plaintext
	 * @return message signaure
	 */
	String signMessage(String message);
}
