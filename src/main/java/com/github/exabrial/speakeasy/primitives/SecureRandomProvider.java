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

import java.security.SecureRandom;

/**
 * Provides an instance of a secure random. Implementations made provide
 * security, concurrency, or performance guarantees.
 */
public interface SecureRandomProvider {
	/**
	 * Borrow a secure random. Callers should not store references that exist beyond
	 * their local context. Best practice is to ALWAYS call borrowSecureRandom() and
	 * never ever ever assign it to a reference.
	 * 
	 * @return a SecureRandom
	 */
	SecureRandom borrowSecureRandom();
}
