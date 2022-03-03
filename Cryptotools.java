import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
//import java.util.concurrent.TimeUnit;
import java.security.PrivateKey;
import java.security.PublicKey;
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
      key,"AES/CBC/PKCS5Padding"
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
      key,"AES/CBC/PKCS5Padding"
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
      key,"AES/CBC/PKCS5Padding"
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
      key,"AES/CBC/PKCS5Padding"
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
      key,"AES/CTR/NoPadding"
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
      key,"AES/CTR/NoPadding"
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
      key,"AES/CTR/NoPadding"
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
      key,"AES/CTR/NoPadding"
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
    SecretKey key1 = kgen1.generateKey();
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
      key1,"AES/CTR/NoPadding"
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
      key1,"AES/CTR/NoPadding"
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
      key1,"AES/CTR/NoPadding"
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
      key1,"AES/CTR/NoPadding"
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
    // // File("SmallFileEncryptedCTR256.txt"), key1);
    // byte[] encBytes = rsa.encrypt(dataBytes, publicKey);
    // try (FileOutputStream fos = new FileOutputStream("smallFileRSA.txt")) {
    // 	fos.write(encBytes);
    // 	//fos.close(); There is no more need for this line since you had created the instance of "fos" inside the try. And this will automatically close the OutputStream
    //  }
    // long rsaEncryptEnd = System.nanoTime();
    // System.out.println(
    // 		"Total time to encrypt small file using RSA key" + (rsaEncryptEnd - rsaEncryptStart));
    // ####### HASH VALUE CALCULATION ############

    //SMALL FILE
    String[] HashArray = { "SHA-256", "SHA-512", "SHA3-256" };
    int m;
    for (m = 0; m < 3; m++) {
      MessageDigest md = MessageDigest.getInstance(HashArray[m]);

      long hashStart = System.nanoTime();

      FileInputStream fis = new FileInputStream("smallFile_1KB.txt");
      byte[] dataBytes = new byte[1024];

      int nread = 0;
      while ((nread = fis.read(dataBytes)) != -1) {
        md.update(dataBytes, 0, nread);
      }
      fis.close();

      byte[] mdbytes = md.digest();

      long hashEnd = System.nanoTime();

      StringBuffer sb = new StringBuffer();
      for (int i = 0; i < mdbytes.length; i++) {
        sb.append(
          Integer.toString((mdbytes[i] & 0xff) + 0x100, 16).substring(1)
        );
      }

      long hashTime = (hashEnd - hashStart);
      System.out.println(
        HashArray[m] + "- Hashing time in nanoseconds - SMALL FILE " + hashTime
      );

      // LARGE FILE
      MessageDigest md2 = MessageDigest.getInstance(HashArray[m]);
      hashStart = System.nanoTime();
      FileInputStream fis1 = new FileInputStream("largeFile_1MB.txt");
      dataBytes = new byte[1024];
      nread = 0;
      while ((nread = fis1.read(dataBytes)) != -1) {
        md2.update(dataBytes, 0, nread);
      }
      fis1.close();

      byte[] mdbytes1 = md2.digest();

      hashEnd = System.nanoTime();
      StringBuffer sb1 = new StringBuffer();
      for (int i = 0; i < mdbytes1.length; i++) {
        sb1.append(
          Integer.toString((mdbytes1[i] & 0xff) + 0x100, 16).substring(1)
        );
      }
      hashTime = (hashEnd - hashStart);
      System.out.println(
        HashArray[m] + "- Hashing time in nanoseconds- LARGE FILE" + hashTime
      );
    }
  }
}
