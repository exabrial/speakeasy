package com.github.exabrial.speakeasy.asymmetric;

import java.security.PrivateKey;

import com.github.exabrial.speakeasy.primitives.keys.SpeakEasyKey;

public interface SpeakEasyPrivateKey extends SpeakEasyKey {
	PrivateKey toKey();
}
