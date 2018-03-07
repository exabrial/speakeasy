package com.github.exabrial.speakeasy.primitaves;

import javax.crypto.Cipher;

public enum CipherMode {
	Encrypt(Cipher.ENCRYPT_MODE), Decrypt(Cipher.DECRYPT_MODE);

	public int value;

	CipherMode(int mode) {
		this.value = mode;
	}
}
