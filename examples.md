# Speakeasy Examples and Documentation

## Decrypter/Encrypter

### Use for
* Encrypting a secret in a way only the person possessing the correct key can decrypt it.
* Masks the exact length of the plaintext.
* Encrypting the same thing twice with the same key will yield different cipherTexts.

### Don't Use For
* Don't attempt to use an encryption algorithm as a hash. This will result in an extraordinarily embarrassing hack of your stuff.

### Types

#### Asymmetric
* The public key can encrypt, but *only* the private key can decrypt.

##### ECIES
* Likely the best choice for securing data.
* EC is P-256, KDF is SHA256, MAC is HMAC-SHA256, cipher is AES-GCM (128 bit).
* Uses a Diffie-Helman exchange to create an emphermal AES key.
* Not compatible with other ECIES implementations (in fact, it seems very hard to do this, as there is no official specification).

#### Symmetric
* Same key is used to encrypt and decrypt.

##### AES-GCM
* 128 bit AES encryption running under the GCM [authenticated] cipher mode
* Likely the fastest encryption method.
* Randomized IV is prepended to the encrypted message.


## Fingerprinter
* Take an arbitrary length message, create a much smaller hash value, or fingerprint.
* Given the same message input, you'll get the same fingerprint.
* It's very difficult to go in reverse: start with a fingerprint and create an input that produces said fingerprint.
* The output fingerprint is always a fixed length.
* Changing one bit of the message will result in a massive change in the fingerprint.
* Offers a constant-time `verify()` option to avoid timing attacks.

### Use for
* Determining whether or not a message has been altered, without storing the entire message.

### Don't Use For
* Don't use the Fingerprint class to "hash a user's password". Holy smokes. Just No. 
    * Instead Speakeasy offers the SlowHash class that wraps scrypt
    
    
#### Non-Keyed

##### SHA-256
* Very fast
* Doesnt require a secret key

#### Symmetric

##### HMACS-SHA256

* Makes use of HMAC-SHA256
* Anyone that posses the key can create valid fingerprints

#### Asymmetric
 
* See Signer/Verifier


 