package com.github.exabrial.speakeasy.primitives;

public interface MessageComporator {
  boolean compare(String calculatedFingerPrint, String presentedFingerPrint);
}
