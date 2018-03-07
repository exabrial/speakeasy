package com.github.exabrial.speakeasy.primitaves;

import java.security.Key;

public interface SpeakEasyKey {
	byte[] getKeyBytes();

	Key toKey();
}
