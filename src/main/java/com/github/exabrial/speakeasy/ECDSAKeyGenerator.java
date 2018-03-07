package com.github.exabrial.speakeasy;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ECDSAKeyGenerator {
  public static final String SIG_ALG = "SHA256withECDSA";
  public static final String EC_CURVE_NAME = "secp256r1";
  public static final String GEN_ALG = "EC";

  private ECDSAKeyGenerator() {
  }

  public static void main(String[] args) throws Exception {
    KeyPair keyPair = generateKeyPair();
    System.out.println("Public:" + toString(keyPair.getPublic()));
    System.out.println("Private:" + toString(keyPair.getPrivate()));
  }

  public static KeyPair generateKeyPair() {
    try {
      SecureRandom secureRandom = SecureRandom.getInstanceStrong();
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(GEN_ALG);
      ECGenParameterSpec ecSpec = new ECGenParameterSpec(EC_CURVE_NAME);
      keyGen.initialize(ecSpec, secureRandom);
      return keyGen.generateKeyPair();
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  public static String toString(Key key) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(GEN_ALG);
      Class<? extends EncodedKeySpec> keySpecClass;
      if (key instanceof PublicKey) {
        keySpecClass = X509EncodedKeySpec.class;
      } else if (key instanceof PrivateKey) {
        keySpecClass = PKCS8EncodedKeySpec.class;
      } else {
        throw new RuntimeException("Key type not supported");
      }
      EncodedKeySpec spec = keyFactory.getKeySpec(key, keySpecClass);
      return new String(Base64.getEncoder().encode(spec.getEncoded()), UTF_8);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}
