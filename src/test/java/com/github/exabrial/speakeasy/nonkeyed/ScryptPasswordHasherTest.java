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
package com.github.exabrial.speakeasy.nonkeyed;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ScryptPasswordHasherTest {
  private final String pass = "It is often that a person’s mouth broke his nose";

  @Test
  public void testMaskPassword_checkPassword() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertTrue(hasher.checkPassword(pass, hash));
  }

  @Test
  public void testMaskPassword_checkPassword_modHash() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(pass, "totallyRandomBase64" + hash));
  }

  @Test
  public void testMaskPassword_checkPassword_modPw() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(pass + "password", hash));
  }

  @Test
  public void testMaskPassword_checkPassword_nullHash() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(pass, null));
  }

  @Test
  public void testMaskPassword_checkPassword_nullPass() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(null, hash));
  }

  @Test
  public void testMaskPassword_checkPassword_shortHash() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(pass, hash.substring(5)));
  }

  @Test
  public void testMaskPassword_checkPassword_shortPass() {
    final ScryptPasswordHasher hasher = new ScryptPasswordHasher();
    final String hash = hasher.hashPassword(pass);
    System.out.println(hash);
    assertFalse(hasher.checkPassword(pass.substring(5), hash));
  }
}
