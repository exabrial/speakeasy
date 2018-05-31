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
 * A Verifier will check that a signature was produced by a corresponding
 * Signer.
 */
public interface Verifier {
	/**
	 * Checks whether or not a signature was produced by a corresponding signer.
	 * TODO: Set the log level to trace to see stack traces when errors occur.
	 *
	 * @param message
	 *          plaintext
	 * @param signature
	 *          provided signature to verify
	 * @return returns true if the signature matches, or false if the signature is
	 *         invalid, or false if an error occurs.
	 */
	boolean verifyMessageSignature(String message, String signature);
}
