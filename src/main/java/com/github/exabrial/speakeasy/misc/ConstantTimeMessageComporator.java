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

package com.github.exabrial.speakeasy.misc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.HMACSHA256_SIG_LENGTH;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Compare two strings in O(n) time, even if one of the strings is shorter or
 * doesn't match.
 */
public class ConstantTimeMessageComporator implements MessageComporator {
	private final StringEncoder stringEncoder;

	public static ConstantTimeMessageComporator getSingleton() {
		return Singleton.Instance.messageComporator;
	}

	public ConstantTimeMessageComporator() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
	}

	public ConstantTimeMessageComporator(final Base64StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
	}

	@Override
	public boolean compare(final String calculatedFingerprint, final String presentedFingerprint) {
		final byte[] calculatedSignatureBytes = getBytes(calculatedFingerprint, HMACSHA256_SIG_LENGTH);
		final byte[] presentedSignatureBytes = getBytes(presentedFingerprint, HMACSHA256_SIG_LENGTH);
		return internalCompare(calculatedSignatureBytes, presentedSignatureBytes);
	}

	private byte[] getBytes(final String signature, final int length) {
		byte[] presentedSignatureBytes;
		try {
			presentedSignatureBytes = stringEncoder.decodeStringToBytes(signature);
		} catch (final Exception e) {
			presentedSignatureBytes = new byte[length];
		}
		return presentedSignatureBytes;
	}

	private static boolean internalCompare(final byte[] calculatedSignatureBytes, final byte[] presentedSignatureBytes) {
		boolean isValid = true;
		// Arrays.equals would be great
		// MAC comparisons should be constant time however
		for (int index = 0; index < calculatedSignatureBytes.length; index++) {
			final byte cByte = calculatedSignatureBytes[index];
			if (index < presentedSignatureBytes.length) {
				final byte pByte = presentedSignatureBytes[index];
				if (isValid) {
					isValid = cByte == pByte;
				}
			} else {
				isValid = false;
			}
		}
		return isValid;
	}

	private enum Singleton {
		Instance;
		private final ConstantTimeMessageComporator messageComporator;

		Singleton() {
			this.messageComporator = new ConstantTimeMessageComporator();
		}
	}
}
