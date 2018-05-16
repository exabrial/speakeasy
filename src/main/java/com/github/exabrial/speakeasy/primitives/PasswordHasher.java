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
 * Similar to a Fingerprint, a PasswordHash is a deterministic hash-function
 * who's fixed-length output is stable for a given arbitrarily-sized input.
 * Whereas a Fingerprint is designed to be very fast, a PasswordHash is designed
 * to be very slow. This makes it difficult for an attacker to brute force
 * search a plaitnext for a given password hash.
 */
public interface PasswordHasher {
	/**
	 * Compute the hash for a password.
	 * 
	 * @param password
	 *          plaintext password
	 * @return hash
	 */
	String hashPassword(String password);

	/**
	 * Checks to see if a plaintext password hashes to the given hash. TODO: Turn on
	 * logging at the trace level to receive stack traces for errors.
	 * 
	 * @param password
	 *          plaintext password
	 * @param hash
	 *          the hash to compare against
	 * @return true if the resulting password hash equals the provided hash, false
	 *         if it does not, or false if there is an error.
	 */
	boolean checkPassword(String password, String hash);
}
