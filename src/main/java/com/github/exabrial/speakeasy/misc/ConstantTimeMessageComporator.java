package com.github.exabrial.speakeasy.misc;

import static com.github.exabrial.speakeasy.internal.SpeakEasyConstants.HMACSHA256_SIG_LENGTH;

import com.github.exabrial.speakeasy.encoding.Base64StringEncoder;
import com.github.exabrial.speakeasy.encoding.StringEncoder;
import com.github.exabrial.speakeasy.primitives.MessageComporator;

public class ConstantTimeMessageComporator implements MessageComporator {
  public static MessageComporator getSingleton() {
    return Singleton.Instance.messageComporator;
  }

  private static enum Singleton {
    Instance;
    public final ConstantTimeMessageComporator messageComporator;

    Singleton() {
      this.messageComporator = new ConstantTimeMessageComporator();
    }
  }

  private final StringEncoder stringEncoder;

  public ConstantTimeMessageComporator() {
    this.stringEncoder = Base64StringEncoder.getSingleton();
  }

  public ConstantTimeMessageComporator(final Base64StringEncoder stringEncoder) {
    this.stringEncoder = stringEncoder;
  }

  @Override
  public boolean compare(final String calculatedFingerPrint, final String presentedFingerPrint) {
    final byte[] cSignatureBytes = getBytes(calculatedFingerPrint, HMACSHA256_SIG_LENGTH);
    final byte[] pSignatureBytes = getBytes(presentedFingerPrint, HMACSHA256_SIG_LENGTH);
    return compare(cSignatureBytes, pSignatureBytes);
  }

  private byte[] getBytes(final String signature, final int length) {
    byte[] pSignatureBytes;
    try {
      pSignatureBytes = stringEncoder.decodeStringToBytes(signature);
    } catch (final Exception e) {
      pSignatureBytes = new byte[length];
    }
    return pSignatureBytes;
  }

  private static boolean compare(final byte[] cSignatureBytes, final byte[] pSignatureBytes) {
    boolean isValid = true;
    // Arrays.equals would be great
    // MAC comparisons should be constant time however
    for (int i = 0; i < cSignatureBytes.length; i++) {
      final byte cByte = cSignatureBytes[i];
      if (i < pSignatureBytes.length) {
        final byte pByte = pSignatureBytes[i];
        if (isValid) {
          isValid = cByte == pByte;
        }
      } else {
        isValid = false;
      }
    }
    return isValid;
  }
}
