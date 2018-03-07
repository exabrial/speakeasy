package com.github.exabrial.speakeasy.asymmetric;

import java.security.PublicKey;

import com.github.exabrial.speakeasy.primitives.keys.SpeakEasyKey;

public interface SpeakEasyPublicKey extends SpeakEasyKey {
	PublicKey toKey();
}
