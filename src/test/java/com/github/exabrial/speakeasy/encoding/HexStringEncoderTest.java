package com.github.exabrial.speakeasy.encoding;

import java.util.Arrays;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class HexStringEncoderTest {
  private final HexStringEncoder encoder = HexStringEncoder.getSingleton();
  private final byte[] testVectorBytes = new byte[] { 0x01, 0x02, 0x03, 0x4, 0x5, 0x6, 0x7 };
  private final String testVectorString = "01020304050607";

  @Test
  public void testEncodeBytesAsString() {
    String encodeBytesAsString = encoder.encodeBytesAsString(testVectorBytes);
    assertEquals(testVectorString, encodeBytesAsString);
  }

  @Test
  public void testDecodeStringToBytes() {
    byte[] decodeStringToBytes = encoder.decodeStringToBytes(testVectorString);
    assertTrue(Arrays.equals(decodeStringToBytes, testVectorBytes));
  }
}
