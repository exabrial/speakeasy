package com.github.exabrial.speakeasy;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ECDSASigner {
  private final PrivateKey privateKey;
  private SecureRandom secureRandom;

  public ECDSASigner(PrivateKey privateKey) {
    try {
      secureRandom = SecureRandom.getInstanceStrong();
      this.privateKey = privateKey;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public ECDSASigner(String encodedPrivateKey) {
    try {
      secureRandom = SecureRandom.getInstanceStrong();
      byte[] keyBytes = Base64.getDecoder().decode(encodedPrivateKey.getBytes(UTF_8));
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
      privateKey = keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public String signPlaintext(String plaintext) {
    try {
      byte[] signatureBytes;
      synchronized (secureRandom) {
        Signature ecdsa = Signature.getInstance(SIG_ALG);
        ecdsa.initSign(privateKey, secureRandom);
        ecdsa.update(plaintext.getBytes(UTF_8));
        signatureBytes = ecdsa.sign();
      }
      String signature = new String(Base64.getEncoder().encode(signatureBytes), UTF_8);
      return signature;
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }
}
