# Speakeasy
Speakeasy - Plain Simple Cryptography that makes it hard to do the wrong thing

## Preamble

* Most cryptographic bugs in Java code are not from the JCE, but because outdated, bad, or malevolent advice in Stack Exchange or GitHub Gists.
* The JCE gives you a lot of primitives, but not a lot of direction.
* This library is not "implementing your own crypto", but "using the crypto you already have correctly".
* Basically, just read this: https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2009/july/if-youre-typing-the-letters-a-e-s-into-your-code-youre-doing-it-wrong/

## How To Use

Start in the `com.github.exabrial.speakeasy.primitives` package and look at the interfaces. Every cryptographic primitive is represented by a Java interface. 

## Quick Examples

How to hash something with Speakeasy:

```
public class MyThing {
	// Wahoo no stupid checked exceptions!
	private final Fingerprinter fingerprinter = new SHA256Fingerprinter();

	public String doSomeMagic(String testVector) {
		// Even better, I'm Thread safe!
		String fingerprint = fingerprinter.fingerprint(testVector);
		....
	}
}
```

How to encrypt something with Speakeasy:

```
public class MyThing {
	private final SymmetricKeyUtils utils = new SymmetricKeyUtils();
	// Properly and Securely generate a key 
	private final SymmetricKey sharedKey = utils.generateSecureSymmetricKey();
	// Wahoo no stupid checked exceptions!
	private final Encrypter encrypter = new AESGCMEncrypter(sharedKey);

	public String doSomeMagic(String plainText) {
		final String cipherText = encrypter.encrypt(plainText);
		...
	}
	
	public String saveKey() {
		// Me save dis for later
		return utils.toString(sharedKey);
	}
}
```


## Goals

* Expose simple interfaces to the programmer
* Be DI framework friendly
* Be thread safe
* Be easy to debug
* Be opinionated about algorithm choices (ECIES, ECDSA, SHA2, AES-GCM, RSA, ect)
* Be opinionated about key sizes for the user
* Make it easy to the right thing, difficult to the wrong thing
* Get rid of the checked exception mess in the JCE
* Use the type system to check for bugs the JCE does not allow you to do

## Not Goals

* Invent or implement own crypto. That sort of fun will be in another project
* Support MD5, SHA1, RSA < 2048, Non-NIST Elliptic Curves, but maybe Ed25519s
* < JDK 1.8 support (Using a dated JDK and concerned about security, really?)
* Side channel attacks. Hire a crypto expert instead

## Currently Supported Algs

* ECDSA
* SHA256, SHA384, SHA512
* Blake2b-256, 384, 512 (non-keyed)
* AES128
* HMAC-SHA256
* RSA Signatures


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

**ALL** files in this project are licensed. See [LICENSE.md](LICENSE.md)

Note that this project's binary artifacts repackage small elements of the BouncyCastle Cryptography library; those parts retain their original MIT License.

## Contributing

Yay! See [CONTRIBUTING.md](CONTRIBUTING.md)


## Downloading

### Using Maven:


```
<dependency>
	<groupId>com.github.exabrial</groupId>
	<artifactId>speakeasy</artifactId>
	<version>1.0.0</version>
	<scope>compile</scope>
</dependency>
```

I highly recommend you add `pgpverify-maven-plugin` to your pom to check signatures on your artifacts. You can see how this is done by looking at Speakeasy's pom.

## Building

* Install homebrew
* Install gpg, either MacGPG or homebrew gpg
* Set gpg and it's agent up
* `brew cask install java8`
* `brew install maven`

Currently, Speakeasy targets JDK 1.8. You will need a `~/.m2/toolchains.xml` file that points to a JDK 8 installation. An example file is included in this project.

After that, simply run: `mvn install`. In your IDE, you can enable the `eclipse` profile to bring in the Junit5 dependencies. You can skip all the checks by running `mvn install -P skipChecks` for prototype builds... obviously don't do that long term. Finally there is a site you can run to see HTML reports of the project: `mvn clean site`. After this is complete, open the `target/site/index.html` file.

## TODO List
* SHA3: 256, 384, 512
* Argon, Scrypt, Bcrypt
* EdDSA signatures
* Curve25519 for ECDSA
* ECIES
