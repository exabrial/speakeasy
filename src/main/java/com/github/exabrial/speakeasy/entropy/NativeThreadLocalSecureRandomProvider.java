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

package com.github.exabrial.speakeasy.entropy;

import java.lang.ref.WeakReference;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;

/**
 * Attempts to use platform native random generators. The output from the
 * platform native generator is XOR'd with output from software generator. If
 * platform native cannot be used, this will select the strongest random
 * generator type available.<br/>
 * A SecureRandom returned by this implementation is created for EACH thread and
 * held using a WeakReference. Don't hold a reference objects returned outside
 * of your local scope. Best practice is to just call borrowSecureRandom()
 * _every_ time and allow the JIT to optimize your code properly.<br/>
 * <br/>
 * Important info about /dev/random and /dev/urandom <br/>
 * https://bit.ly/2IvSuaI <br/>
 * https://bit.ly/2En8fOI
 */
public class NativeThreadLocalSecureRandomProvider implements SecureRandomProvider {
	private static final String NATIVE_PRNG = "NativePRNG";
	private static final String SUN = "SUN";
	private static final ThreadLocal<WeakReference<SecureRandom>> threadLocal = new ThreadLocal<>();

	public static NativeThreadLocalSecureRandomProvider getSingleton() {
		return Singleton.Instance.provider;
	}

	@Override
	public SecureRandom borrowSecureRandom() {
		WeakReference<SecureRandom> weakReference = threadLocal.get();
		SecureRandom secureRandom;
		if (weakReference != null) {
			secureRandom = weakReference.get();
		} else {
			secureRandom = null;
		}
		if (secureRandom == null) {
			try {
				// Attempt to use non-blocking native RNG with xor PRNG.
				secureRandom = SecureRandom.getInstance(NATIVE_PRNG, SUN);
			} catch (final NoSuchAlgorithmException e) {
				try {
					// Probably on winblows, sigh. Retreat.
					System.err
							.println("WARN: NativePRNG not available, weaker RNG being used. It may not be a good idea to use this VM to do ANY ECC "
									+ "operations, as it may be result in complete revelation of the secret keys");
					secureRandom = SecureRandom.getInstanceStrong();
				} catch (final NoSuchAlgorithmException e1) {
					throw new RuntimeException(e1);
				}
			} catch (final NoSuchProviderException e) {
				throw new RuntimeException(e);
			}
			// Because America. Why not?
			final byte[] seed = SecureRandom.getSeed(55);
			secureRandom.setSeed(seed);
			threadLocal.set(new WeakReference<SecureRandom>(secureRandom));
		}
		return secureRandom;
	}

	private enum Singleton {
		Instance;
		public final NativeThreadLocalSecureRandomProvider provider;

		Singleton() {
			this.provider = new NativeThreadLocalSecureRandomProvider();
		}
	}
}
