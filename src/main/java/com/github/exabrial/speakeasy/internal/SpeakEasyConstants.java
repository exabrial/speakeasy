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

import java.security.Security;
import java.util.Arrays;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;

public final class SpeakEasyConstants {
  public static final int PKDF_ITERATIONS = 4096;
  public static final int AES_KEY_SIZE = 128;
  public static final String AES = "AES";
  public static final String AES_GCM = "AES/GCM/PKCS5Padding";
  public static final int GCM_NONCE_LENGTH = 12;
  public static final int AES_GCM_TAG_LENGTH = 128;
  public static final String EC = "EC";
  public static final String EC_SIG_ALG = "SHA256withECDSA";
  public static final String EC_CURVE_NAME = "secp256r1";
  public static final String SHA256 = "SHA256";
  public static final String HMAC_SHA256 = "HmacSHA256";
  public static final int HMACSHA256_SIG_LENGTH = 32;
  public static final IESParameterSpec IES_PARAMATER_SPEC;
  static {
    if (Arrays.asList(Security.getProviders()).stream()
        .filter(provider -> provider.getName().equals(BouncyCastleProvider.PROVIDER_NAME)).findFirst()
        .orElse(null) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
    // Normally, this would be very stupid. However, a fixed nonce is ok when using
    // ECIES, because the ephemeral key is never repeated.
    final byte[] nonce = new byte[GCM_NONCE_LENGTH];
    Arrays.fill(nonce, Byte.MIN_VALUE);
    IES_PARAMATER_SPEC = new IESParameterSpec(null, null, 128, 128, nonce);
  }

  private SpeakEasyConstants() {
  }
}
