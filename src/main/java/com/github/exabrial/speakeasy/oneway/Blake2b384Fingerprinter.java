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

package com.github.exabrial.speakeasy.oneway;

import java.security.NoSuchAlgorithmException;

import com.github.exabrial.speakeasy.comporator.BasicMessageComporator;
import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

/**
 * Blake2b is _the fastest_ cryptographic hash algorithm available, it's much
 * faster than md5 and sha1, but offers none of the security problems. This
 * implementation uses a "self-keying" construction.
 */
public class Blake2b384Fingerprinter extends FingerprinterBase {
	private final StringEncoder stringEncoder;
	private final MessageComporator messageComporator;

	public Blake2b384Fingerprinter() {
		this.stringEncoder = Base64StringEncoder.getSingleton();
		this.messageComporator = BasicMessageComporator.getSingleton();
	}

	public Blake2b384Fingerprinter(final StringEncoder stringEncoder) {
		this.stringEncoder = stringEncoder;
		this.messageComporator = BasicMessageComporator.getSingleton();
	}

	public Blake2b384Fingerprinter(final StringEncoder stringEncoder, final MessageComporator messageComporator) {
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
	MessageDigester getDigester() throws NoSuchAlgorithmException {
		return new Blake2bMessageDigester(null, 384);
	}
}
