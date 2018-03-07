package com.github.exabrial.speakeasy.primitives.keys;

import java.security.Key;

public interface SpeakEasyKey {
	byte[] getKeyBytes();

	Key toKey();
}
