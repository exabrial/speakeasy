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

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.EC;

import java.security.PrivateKey;

import com.github.exabrial.speakeasy.asymmetric.SpeakEasyPrivateKey;

public class SpeakEasyEccPrivateKey implements SpeakEasyPrivateKey {
  private final PrivateKey privateKey;

  SpeakEasyEccPrivateKey(final PrivateKey privateKey) {
    if (!privateKey.getAlgorithm().equals(EC)) {
      // TODO
      throw new RuntimeException("unsupportted alg");
    } else {
      this.privateKey = privateKey;
    }
  }

  @Override
  public byte[] getKeyBytes() {
    return privateKey.getEncoded();
  }

  @Override
  public PrivateKey toKey() {
    return privateKey;
  }
}
