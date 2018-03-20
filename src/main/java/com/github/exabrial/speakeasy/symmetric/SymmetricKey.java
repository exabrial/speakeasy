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
package com.github.exabrial.speakeasy.symmetric;

import java.security.Key;

import javax.crypto.SecretKey;

import com.github.exabrial.speakeasy.primitives.SpeakEasyKey;

public class SymmetricKey implements SpeakEasyKey {
  private final SecretKey secretKey;

  SymmetricKey(final SecretKey secretKey) {
    // TODO 128?
    this.secretKey = secretKey;
  }

  @Override
  public byte[] getKeyBytes() {
    return secretKey.getEncoded();
  }

  @Override
  public Key toKey() {
    return secretKey;
  }
}
