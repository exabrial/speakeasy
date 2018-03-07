package com.github.exabrial.speakeasy.asymmetric;

public interface AsymmetricKeyUtils<PublicType extends SpeakEasyPublicKey, PrivateType extends SpeakEasyPrivateKey, PairType extends SpeakEasyKeyPair> {
	PairType createKeyPair();

	PublicType readPublicKey(String encodedKeyText);

	PrivateType readPrivateKey(String encodedKeyText);

	String toString(PublicType speakEasyPublicKey);

	String toString(PrivateType speakEasyPrivateKey);
}
