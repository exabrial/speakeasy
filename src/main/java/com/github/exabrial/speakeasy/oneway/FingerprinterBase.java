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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SUN;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import com.github.exabrial.speakeasy.comporator.BasicMessageComporator;
import com.github.exabrial.speakeasy.primitives.Fingerprinter;
import com.github.exabrial.speakeasy.primitives.MessageComporator;
import com.github.exabrial.speakeasy.primitives.StringEncoder;

public abstract class FingerprinterBase implements Fingerprinter {
	abstract String getAlg();

	abstract StringEncoder getStringEncoder();

	MessageComporator getMessageComporator() {
		return BasicMessageComporator.getSingleton();
	}

	Provider getProvider() {
		return Security.getProvider(SUN);
	}

	@Override
	public String fingerprint(final String message) {
		try {
			final byte[] fingerprintBytes = digest(message);
			final String fingerprint = getStringEncoder().encodeBytesAsString(fingerprintBytes);
			return fingerprint;
		} catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean verifyFingerprint(final String message, final String fingerprint) {
		try {
			final byte[] calculatedFingerprintBytes = digest(message);
			final byte[] presentedFingerprintBytes = getStringEncoder().decodeStringToBytes(fingerprint);
			final boolean equals = getMessageComporator().compare(calculatedFingerprintBytes, presentedFingerprintBytes);
			return equals;
		} catch (final NullPointerException | ArrayIndexOutOfBoundsException e) {
			return false;
		} catch (final NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}

	private byte[] digest(final String message) throws NoSuchAlgorithmException, NoSuchProviderException {
		final byte[] messageBytes = getStringEncoder().getStringAsBytes(message);
		final MessageDigest digest = MessageDigest.getInstance(getAlg(), getProvider());
		final byte[] fingerprintBytes = digest.digest(messageBytes);
		return fingerprintBytes;
	}
}
