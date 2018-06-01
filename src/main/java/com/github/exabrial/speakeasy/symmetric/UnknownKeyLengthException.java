package com.github.exabrial.speakeasy.symmetric;

/**
 * Thrown if the keyLength doesn't map to a class.
 *
 */
public class UnknownKeyLengthException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public UnknownKeyLengthException(final byte[] keyBytes) {
		super(String.format("Key length:%d doesn't match a class", keyBytes.length));
	}

}
