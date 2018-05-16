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

package com.github.exabrial.speakeasy.internal;

/**
 * Internal class used to configure key sizes and algs. Good for reference but
 * not really useful to the user.
 */
public final class SpeakEasyConstants {
	public static final int SCRYPT_SIZE = 64;
	public static final int SCRYPT_P = 1;
	public static final int SCRYPT_R = 8;
	public static final int SCRYPT_N = (int) Math.pow(2, 14);
	public static final int AES_KEY_SIZE = 128;
	public static final String AES = "AES";
	public static final String AES_GCM = "AES/GCM/PKCS5Padding";
	public static final int GCM_NONCE_LENGTH = 12;
	public static final int AES_GCM_TAG_LENGTH = 128;
	public static final String EC = "EC";
	public static final String EC_SIG_ALG = "SHA256withECDSA";
	public static final String EC_CURVE_NAME = "secp256r1";
	public static final String SHA256 = "SHA-256";
	public static final String SHA384 = "SHA-384";
	public static final String SHA512 = "SHA-512";
	public static final String HMAC_SHA256 = "HmacSHA256";
	public static final int HMACSHA256_SIG_LENGTH = 32;

	private SpeakEasyConstants() {
	}
}
