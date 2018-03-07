package com.github.exabrial.speakeasy;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECDSAVerifier {
  private final PublicKey publicKey;

  public ECDSAVerifier(PublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public ECDSAVerifier(String encodedPublicKey) {
    try {
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(encodedPublicKey.getBytes(UTF_8)));
      KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
      publicKey = keyFactory.generatePublic(keySpec);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public boolean verifySignature(String plaintext, String signature) {
    try {
      Signature ecdsa = Signature.getInstance(SIG_ALG);
      ecdsa.initVerify(publicKey);
      byte[] plainTextBytes = plaintext.getBytes(UTF_8);
      ecdsa.update(plainTextBytes);
      byte[] signatureBytes = Base64.getDecoder().decode(signature.getBytes(UTF_8));
      return ecdsa.verify(signatureBytes);
    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
      throw new RuntimeException(e);
    }
  }
}
