import java.io.File;
import java.security.MessageDigest;
import javax.crypto.KeyGenerator; // For Key Generaion
import javax.crypto.SecretKey;

public class Cryptotools {

  public static void main(String[] args) throws Exception {
    // 128-bit AES key generation

    long keyStart = System.nanoTime();
    KeyGenerator kgen = KeyGenerator.getInstance("AES");
    kgen.init(128);
    SecretKey key = kgen.generateKey();
    long keyEnd = System.nanoTime();
    System.out.println(
      "Time it take to generate a new key(128 bit)" + (keyEnd - keyStart)
    );

    // ########## CBC MODE 128 bit key ##############

    // Create object of AesEncryptionDecryptionCBC class
    Aes aes = new Aes();
    // #### SMALL FILE - 1KB ####
    // Encrypt
    long cbcEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("smallFile_1KB.txt"),
      new File("SmallFileEncrypted.txt"),
      key,
      "AES/CBC/PKCS5Padding"
    );
    long cbcEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to encrypt small file in CBC mode" +
      (cbcEncryptEnd - cbcEncryptStart)
    );

    // Decrypt
    long cbcDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("SmallFileEncrypted.txt"),
      new File("SmallFileDecrypted.txt"),
      key,
      "AES/CBC/PKCS5Padding"
    );
    long cbcDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt small file in CBC mode" +
      (cbcDecryptEnd - cbcDecryptStart)
    );

    // #### LARGE FILE - 1MB ###
    // Encrypt
    cbcEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("largeFile_1MB.txt"),
      new File("LargeFileEncrypted.txt"),
      key,
      "AES/CBC/PKCS5Padding"
    );
    cbcEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt large file in CBC mode" +
      (cbcDecryptEnd - cbcDecryptStart)
    );

    // Decrypt
    cbcDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("LargeFileEncrypted.txt"),
      new File("LargeFileDecrypted.txt"),
      key,
      "AES/CBC/PKCS5Padding"
    );
    cbcDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt large file in CBC mode" +
      (cbcDecryptEnd - cbcDecryptStart)
    );

    // ########## CTR MODE 128 bit Key ###############

    // ### SMALL FILE - 1KB ###
    // Encrypt
    long ctrEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("smallFile_1KB.txt"),
      new File("SmallFileEncryptedCTR.txt"),
      key,
      "AES/CTR/NoPadding"
    );
    long ctrEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to encrypt small file in CTR mode" +
      (ctrEncryptEnd - ctrEncryptStart)
    );

    // Decrypt
    long ctrDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("SmallFileEncryptedCTR.txt"),
      new File("SmallFileDecryptedCTR.txt"),
      key,
      "AES/CTR/NoPadding"
    );
    long ctrDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt small file in CTR mode" +
      (ctrDecryptEnd - ctrDecryptStart)
    );

    // ### LARGE FILE - 1MB ###

    // Encrypt
    ctrEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("largeFile_1MB.txt"),
      new File("LargeFileEncryptedCTR.txt"),
      key,
      "AES/CTR/NoPadding"
    );
    ctrEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to encrypt large file in CTR mode" +
      (ctrEncryptEnd - ctrEncryptStart)
    );

    // Decrypt
    ctrDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("LargeFileEncryptedCTR.txt"),
      new File("LargeFileDecryptedCTR.txt"),
      key,
      "AES/CTR/NoPadding"
    );
    ctrDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt small file in CTR mode" +
      (ctrDecryptEnd - ctrDecryptStart)
    );

    // ########## CTR MODE 256 bit Key ###############

    // ########## 256 BIT KEY GENERATION ###########
    // https://www.andreafortuna.org/java/java-tips-how-to-fix-the-invalidkeyexception-illegal-key-size-or-default-parameters-runtime/

    keyStart = System.nanoTime();
    KeyGenerator kgen1 = KeyGenerator.getInstance("AES");
    kgen1.init(256);
    SecretKey key256 = kgen1.generateKey();
    keyEnd = System.nanoTime();
    System.out.println(
      "Time it take to generate a new key(256 bit)" + (keyEnd - keyStart)
    );
    // ### SMALL FILE - 1KB ###
    // Encrypt
    ctrEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("smallFile_1KB.txt"),
      new File("SmallFileEncryptedCTR256.txt"),
      key256,
      "AES/CTR/NoPadding"
    );
    ctrEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to encrypt small file in CTR mode using 256 bit key" +
      (ctrEncryptEnd - ctrEncryptStart)
    );

    // Decrypt
    ctrDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("SmallFileEncryptedCTR256.txt"),
      new File("SmallFileDecryptedCTR256.txt"),
      key256,
      "AES/CTR/NoPadding"
    );
    ctrDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt small file in CTR mode using 256 bit key" +
      (ctrDecryptEnd - ctrDecryptStart)
    );

    // ### LARGE FILE - 1MB ###
    // Encrypt
    ctrEncryptStart = System.nanoTime();
    aes.encrypt(
      new File("largeFile_1MB.txt"),
      new File("LargeFileEncryptedCTR256.txt"),
      key256,
      "AES/CTR/NoPadding"
    );
    ctrEncryptEnd = System.nanoTime();
    System.out.println(
      "Total time to encrypt large file in CTR mode using 256 bit key" +
      (ctrEncryptEnd - ctrEncryptStart)
    );

    // Decrypt
    ctrDecryptStart = System.nanoTime();
    aes.decrypt(
      new File("LargeFileEncryptedCTR256.txt"),
      new File("LargeFileDecryptedCTR256.txt"),
      key256,
      "AES/CTR/NoPadding"
    );
    ctrDecryptEnd = System.nanoTime();
    System.out.println(
      "Total time to decrypt large file in CTR mode using 256 bit key" +
      (ctrDecryptEnd - ctrDecryptStart)
    );

    // KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    // generator.initialize(2048);
    // KeyPair pair = generator.generateKeyPair();
    // PrivateKey privateKey = pair.getPrivate();
    // PublicKey publicKey = pair.getPublic();
    // Rsa rsa = new Rsa();
    // byte[] dataBytes = Files.readAllBytes(Paths.get("smallFile_1KB.txt"));
    // long rsaEncryptStart = System.nanoTime();
    // // encrypter2.encrypt(new File("smallFile_1KB.txt"), new
    // // File("SmallFileEncryptedCTR256.txt"), key256);
    // byte[] encBytes = rsa.encrypt(dataBytes, publicKey);
    // try (FileOutputStream fos = new FileOutputStream("smallFileRSA.txt")) {
    // 	fos.write(encBytes);
    // 	//fos.close(); There is no more need for this line since you had created the instance of "fos" inside the try. And this will automatically close the OutputStream
    //  }
    // long rsaEncryptEnd = System.nanoTime();
    // System.out.println(
    // 		"Total time to encrypt small file using RSA key" + (rsaEncryptEnd - rsaEncryptStart));

    // ####### HASH VALUE CALCULATION ############

    ShaHash sha = new ShaHash();

    //Hasing using SHA-256
    long hashStart = System.nanoTime();
    sha.hashing(
      "SHA-256",
      MessageDigest.getInstance("SHA-256"),
      new File("smallFile_1KB.txt")
    );
    long hashEnd = System.nanoTime();
    System.out.println(
      "SHA-256 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );
    hashStart = System.nanoTime();
    sha.hashing(
      "SHA-256",
      MessageDigest.getInstance("SHA-256"),
      new File("largeFile_1MB.txt")
    );
    hashEnd = System.nanoTime();

    System.out.println(
      "SHA-256 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );

    //Hasing using SHA-512
    hashStart = System.nanoTime();
    sha.hashing(
      "SHA-512",
      MessageDigest.getInstance("SHA-512"),
      new File("smallFile_1KB.txt")
    );
    hashEnd = System.nanoTime();
    System.out.println(
      "SHA-512 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );
    hashStart = System.nanoTime();
    sha.hashing(
      "SHA-512",
      MessageDigest.getInstance("SHA-512"),
      new File("largeFile_1MB.txt")
    );
    hashEnd = System.nanoTime();

    System.out.println(
      "SHA-512 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );

    //Hasing using SHA3-256
    hashStart = System.nanoTime();
    sha.hashing(
      "SHA-512",
      MessageDigest.getInstance("SHA3-256"),
      new File("smallFile_1KB.txt")
    );
    hashEnd = System.nanoTime();
    System.out.println(
      "SHA3-256 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );
    hashStart = System.nanoTime();
    sha.hashing(
      "SHA3-256",
      MessageDigest.getInstance("SHA3-256"),
      new File("largeFile_1MB.txt")
    );
    hashEnd = System.nanoTime();

    System.out.println(
      "SHA3-256 - Hashing time in nanoseconds- LARGE FILE" +
      (hashEnd - hashStart)
    );
  }
}
