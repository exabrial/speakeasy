package com.github.exabrial.speakeasy.encoding;

import java.util.Arrays;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class Base64StringEncoderTest {
  private final Base64StringEncoder encoder = Base64StringEncoder.getSingleton();
  private final byte[] rfc4648TestVectorBytes = new byte[] { (byte) 0x14, (byte) 0xfb, (byte) 0x9c, (byte) 0x03,
      (byte) 0xd9, (byte) 0x7e };
  String rfc4648TestVectorString = "FPucA9l+";

  @Test
  public void testEncodeBytesAsString() {
    String encodeBytesAsString = encoder.encodeBytesAsString(rfc4648TestVectorBytes);
    assertEquals(rfc4648TestVectorString, encodeBytesAsString);
  }

  @Test
  public void testDecodeStringToBytes() {
    byte[] decodeStringToBytes = encoder.decodeStringToBytes(rfc4648TestVectorString);
    assertTrue(Arrays.equals(decodeStringToBytes, rfc4648TestVectorBytes));
  }
}
