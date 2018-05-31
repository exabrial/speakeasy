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
 * Compares two messages properly. Implementations may have different security
 * properties, like constant time comparison, or side channel attack resistance.
 */
public interface MessageComporator {
	/**
	 * Compare two messages for equality. TODO: Turn on logging at the trace level
	 * to receive stack traces for errors.
	 *
	 * @param calculatedFingerprint
	 *          the fingerprint freshly calculated by a speakeasy fingerprinter
	 * @param presentedFingerprint
	 *          the fingerprint provided by an untrusted or unauthenticated system
	 * @return true if the fingerprints match, false if they do not, or false if an
	 *         error occurs.
	 */
	boolean compare(byte[] calculatedFingerprint, byte[] presentedFingerprint);
}
