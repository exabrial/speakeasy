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

import java.util.Arrays;

import com.github.exabrial.speakeasy.primitives.MessageComporator;

/**
 * Compare to arrays as quickly as possible.
 */
public class BasicMessageComporator implements MessageComporator {
	public static BasicMessageComporator getSingleton() {
		return Singleton.Instance.messageComporator;
	}

	@Override
	public boolean compare(byte[] calculatedFingerprint, byte[] presentedFingerprint) {
		if (calculatedFingerprint != null && presentedFingerprint != null) {
			return Arrays.equals(calculatedFingerprint, presentedFingerprint);
		} else {
			throw new NullPointerException("fingerprints cannot be null");
		}
	}

	private enum Singleton {
		Instance;
		private final BasicMessageComporator messageComporator;

		Singleton() {
			this.messageComporator = new BasicMessageComporator();
		}
	}
}
