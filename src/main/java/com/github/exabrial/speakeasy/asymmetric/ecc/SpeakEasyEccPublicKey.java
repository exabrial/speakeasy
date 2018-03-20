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
package com.github.exabrial.speakeasy.asymmetric.ecc;

import java.security.PublicKey;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyPublicKey;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC;

public class SpeakEasyEccPublicKey implements SpeakEasyPublicKey {
  public final PublicKey publicKey;

  SpeakEasyEccPublicKey(final PublicKey publicKey) {
    if (!publicKey.getAlgorithm().equals(EC)) {
      // TODO
      throw new RuntimeException("unsupportted alg");
    } else {
      this.publicKey = publicKey;
    }
  }

  @Override
  public byte[] getKeyBytes() {
    return publicKey.getEncoded();
  }

  @Override
  public PublicKey toKey() {
    return publicKey;
  }
}
