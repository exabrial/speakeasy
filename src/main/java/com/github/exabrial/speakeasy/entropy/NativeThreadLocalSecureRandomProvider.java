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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import com.github.exabrial.speakeasy.primitives.SecureRandomProvider;

public class NativeThreadLocalSecureRandomProvider implements SecureRandomProvider {
  private static final String NATIVE_PRNG = "NativePRNG";
  private static final String SUN = "SUN";
  private static final ThreadLocal<SecureRandom> threadLocal = new ThreadLocal<>();

  public static NativeThreadLocalSecureRandomProvider getSingleton() {
    return Singleton.Instance.provider;
  }

  private static enum Singleton {
    Instance;
    public final NativeThreadLocalSecureRandomProvider provider;

    Singleton() {
      this.provider = new NativeThreadLocalSecureRandomProvider();
    }
  }

  @Override
  public SecureRandom borrowSecureRandom() {
    // https://bit.ly/2IvSuaI
    // https://bit.ly/2En8fOI
    SecureRandom secureRandom = threadLocal.get();
    if (secureRandom == null) {
      try {
        // Attempt to use non-blocking native RNG with xor PRNG.
        secureRandom = SecureRandom.getInstance(NATIVE_PRNG, SUN);
      } catch (final NoSuchAlgorithmException e) {
        try {
          // Probably on winblows, sigh. Retreat.
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
      threadLocal.set(secureRandom);
    }
    return secureRandom;
  }
}
