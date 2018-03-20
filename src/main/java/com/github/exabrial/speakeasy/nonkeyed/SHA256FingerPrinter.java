package com.github.exabrial.speakeasy.nonkeyed;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.SHA256;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.primitives.FingerPrinter;

public class SHA256FingerPrinter implements FingerPrinter {
  private final StringEncoder stringEncoder;

  public SHA256FingerPrinter() {
    this.stringEncoder = Base64StringEncoder.getSingleton();
  }

  public SHA256FingerPrinter(final StringEncoder stringEncoder) {
    this.stringEncoder = stringEncoder;
  }

  @Override
  public String fingerPrint(final String message) {
    try {
      final byte[] messageBytes = stringEncoder.getStringAsBytes(message);
      final MessageDigest digest = MessageDigest.getInstance(SHA256);
      final byte[] fingerPrintBytes = digest.digest(messageBytes);
      final String fingerPrint = stringEncoder.encodeBytesAsString(fingerPrintBytes);
      return fingerPrint;
    } catch (final NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
