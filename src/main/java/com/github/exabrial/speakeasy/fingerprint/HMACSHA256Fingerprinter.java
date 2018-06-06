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

package com.github.exabrial.speakeasy.fingerprint;

import com.github.exabrial.speakeasy.comporator.BasicMessageComporator;
import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.StringEncoder;
import com.github.exabrial.speakeasy.symmetric.SymmetricKey128;

/**
 * HMAC takes a standard hash algorithm (Fingerprint) and makes it require a
 * symmetric key in order to produce hashes.
 */
public class HMACSHA256Fingerprinter extends FingerprinterBase {
	private final SymmetricKey128 symmetricKey;
	private final StringEncoder stringEncoder;
	private final MessageComporator messageComporator;

	public HMACSHA256Fingerprinter(final SymmetricKey128 symmetricKey) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.messageComporator = BasicMessageComporator.getSingleton();
	}

	public HMACSHA256Fingerprinter(final SymmetricKey128 symmetricKey, final StringEncoder stringEncoder) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = stringEncoder;
		this.messageComporator = BasicMessageComporator.getSingleton();
	}

	public HMACSHA256Fingerprinter(final SymmetricKey128 symmetricKey, final StringEncoder stringEncoder,
			final MessageComporator messageComporator) {
		this.symmetricKey = symmetricKey;
		this.stringEncoder = stringEncoder;
		this.messageComporator = messageComporator;
	}

	@Override
	StringEncoder getStringEncoder() {
		return stringEncoder;
	}

	@Override
	MessageComporator getMessageComporator() {
		return messageComporator;
	}

	@Override
	MessageDigester getDigester() {
		return new HMACSHA256MessageDigester(symmetricKey.getKeyBytes());
	}
}
