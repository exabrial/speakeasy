# Speakeasy
Speakeasy - Plain Simple Cryptography that makes it hard to do the wrong thing

## Preamble

* The JCE gives you a lot of primitives, but not a lot of direction
* Basically, just read this: https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2009/july/if-youre-typing-the-letters-a-e-s-into-your-code-youre-doing-it-wrong/

## Goals

* Expose simple interfaces to the programmer
* Be DI framework friendly
* Be thread safe
* Be easy to debug
* Be opinionated about algorithm choices (ECIES, ECDSA, SHA2, AES-GCM, RSA, ect)
* Be opinionated about key sizes for the user
* Make it easy to the right thing, difficult to the wrong thing
* Get rid of the checked exception mess in the JCE

## Not Goals

* Invent own crypto
* Support MD5, SHA1, RSA < 2048, Non-NIST Elliptic Curves, but maybe Ed25519s
* Implement algorithms... for now
* < JDK 1.8 support (Using a dated JDK and concerned about security, really?)

## Compatibility

* `openssl ec*` to generate EC keys. 
* `openssl genrsa` to generate RSA keys.
* `openssl dgst -sha256` to hash a string
* ECDSA sign/verify operations with openssl

## Intentional Incompatibility

* `gpg --encrypt` No standard KDF or iterations
* ECIES with other implementations... for now
 * May involve implementing some stuff :/
* Ridiculous key lengths

## License

ALL files in this project are licensed. See [LICENSE.md](LICENSE.md)

## Contributing

Yay! See [CONTRIBUTING.md](CONTRIBUTING.md)

## Examples

See [examples.md](examples.md) or peruse the unit tests

## Building

* Install homebrew
* Install gpg, either MacGPG or homebrew gpg
* Set gpg and it's agent up
* `brew cask install java8`
* `brew install maven`

Currently, Speakeasy targets JDK 1.8. You will need a `~/.m2/toolchains.xml` file that points to a JDK 8 installation. An example file is included in this project.

`mvn install`

## TODO List
* RSA: 2048, 3072, 4096
* SHA3: 256, 384, 512
* Argon, Scrypt, Bcrypt
* EdDSA signatures
* Curve25519 for ECDSA, ECIES
* Hmac over the new Fingerprint algs
