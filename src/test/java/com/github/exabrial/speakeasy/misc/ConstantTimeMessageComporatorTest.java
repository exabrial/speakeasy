package com.github.exabrial.speakeasy.misc;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class ConstantTimeMessageComporatorTest {
  private final ConstantTimeMessageComporator comporator = ConstantTimeMessageComporator.getSingleton();

  @Test
  public void testCompare() {
    assertTrue(comporator.compare("calculatedFingerprint", "calculatedFingerprint"));
  }

  @Test
  public void testCompare_false() {
    assertFalse(comporator.compare("calculatedFingerprint", "NotcalculatedFingerprint"));
  }

  @Test
  public void testCompare_false2() {
    assertFalse(comporator.compare("NotcalculatedFingerprint", "calculatedFingerprint"));
  }
}
