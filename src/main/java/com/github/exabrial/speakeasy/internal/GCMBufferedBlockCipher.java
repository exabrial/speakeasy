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
	public void init(boolean forEncryption, CipherParameters params) throws IllegalArgumentException {
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
	public boolean equals(Object obj) {
		return gcmBlockCipher.equals(obj);
	}

	@Override
	public byte[] getMac() {
		return gcmBlockCipher.getMac();
	}

	@Override
	public int getOutputSize(int len) {
		return gcmBlockCipher.getOutputSize(len);
	}

	@Override
	public int getUpdateOutputSize(int len) {
		return gcmBlockCipher.getUpdateOutputSize(len);
	}

	@Override
	public void processAADByte(byte in) {
		gcmBlockCipher.processAADByte(in);
	}

	@Override
	public void processAADBytes(byte[] in, int inOff, int len) {
		gcmBlockCipher.processAADBytes(in, inOff, len);
	}

	@Override
	public int processByte(byte in, byte[] out, int outOff) throws DataLengthException {
		return gcmBlockCipher.processByte(in, out, outOff);
	}

	@Override
	public String toString() {
		return gcmBlockCipher.toString();
	}

	@Override
	public int processBytes(byte[] in, int inOff, int len, byte[] out, int outOff) throws DataLengthException {
		return gcmBlockCipher.processBytes(in, inOff, len, out, outOff);
	}

	@Override
	public int doFinal(byte[] out, int outOff) throws IllegalStateException, InvalidCipherTextException {
		return gcmBlockCipher.doFinal(out, outOff);
	}

	@Override
	public String getAlgorithmName() {
		return gcmBlockCipher.getAlgorithmName();
	}
}
