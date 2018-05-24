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

package com.github.exabrial.speakeasy.comporator;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import com.github.exabrial.speakeasy.primitives.MessageComporator;

/**
 * Compare two strings in O(n) time, even if one of the strings is shorter or
 * doesn't match.
 */
public class SecureMessageComporator implements MessageComporator {
	private static final Random random = new Random(new BigInteger(SecureRandom.getSeed(32)).longValue());

	public static SecureMessageComporator getSingleton() {
		return Singleton.Instance.messageComporator;
	}

	@Override
	public boolean compare(final byte[] calculatedFingerprint, byte[] presentedFingerprint) {
		try {
			Thread.sleep(random.nextInt(6));
		} catch (InterruptedException e) {
			throw new RuntimeException(e);
		}
		boolean isValid = true;
		if (calculatedFingerprint != null && presentedFingerprint != null) {
			if (presentedFingerprint.length != calculatedFingerprint.length) {
				presentedFingerprint = new byte[presentedFingerprint.length];
				isValid = false;
			}
			for (int index = 0; index < calculatedFingerprint.length; index++) {
				final byte cByte = calculatedFingerprint[index];
				if (index < presentedFingerprint.length) {
					final byte pByte = presentedFingerprint[index];
					if (isValid) {
						isValid = cByte == pByte;
					}
				} else {
					isValid = false;
				}
			}
		} else {
			throw new NullPointerException("fingerprints cannot be null");
		}
		return isValid;
	}

	private enum Singleton {
		Instance;
		private final SecureMessageComporator messageComporator;

		Singleton() {
			this.messageComporator = new SecureMessageComporator();
		}
	}
}
