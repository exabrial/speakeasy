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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;

public class GCMBufferedBlockCipher extends BufferedBlockCipher implements AEADBlockCipher {
  private final GCMBlockCipher gcmBlockCipher;

  public GCMBufferedBlockCipher(final BlockCipher blockCipher) {
    gcmBlockCipher = new GCMBlockCipher(blockCipher);
  }

  @Override
  public void init(final boolean forEncryption, final CipherParameters params) throws IllegalArgumentException {
    gcmBlockCipher.init(forEncryption, params);
  }

  @Override
  public int getBlockSize() {
    return gcmBlockCipher.getUnderlyingCipher().getBlockSize();
  }

  @Override
  public void reset() {
    gcmBlockCipher.reset();
  }

  @Override
  public int hashCode() {
    return gcmBlockCipher.hashCode();
  }

  @Override
  public BlockCipher getUnderlyingCipher() {
    return gcmBlockCipher.getUnderlyingCipher();
  }

  @Override
  public boolean equals(final Object obj) {
    return gcmBlockCipher.equals(obj);
  }

  @Override
  public byte[] getMac() {
    return gcmBlockCipher.getMac();
  }

  @Override
  public int getOutputSize(final int len) {
    return gcmBlockCipher.getOutputSize(len);
  }

  @Override
  public int getUpdateOutputSize(final int len) {
    return gcmBlockCipher.getUpdateOutputSize(len);
  }

  @Override
  public void processAADByte(final byte in) {
    gcmBlockCipher.processAADByte(in);
  }

  @Override
  public void processAADBytes(final byte[] in, final int inOff, final int len) {
    gcmBlockCipher.processAADBytes(in, inOff, len);
  }

  @Override
  public int processByte(final byte in, final byte[] out, final int outOff) throws DataLengthException {
    return gcmBlockCipher.processByte(in, out, outOff);
  }

  @Override
  public String toString() {
    return gcmBlockCipher.toString();
  }

  @Override
  public int processBytes(final byte[] in, final int inOff, final int len, final byte[] out, final int outOff)
      throws DataLengthException {
    return gcmBlockCipher.processBytes(in, inOff, len, out, outOff);
  }

  @Override
  public int doFinal(final byte[] out, final int outOff) throws IllegalStateException, InvalidCipherTextException {
    return gcmBlockCipher.doFinal(out, outOff);
  }

  @Override
  public String getAlgorithmName() {
    return gcmBlockCipher.getAlgorithmName();
  }
}
