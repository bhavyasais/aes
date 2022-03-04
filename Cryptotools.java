// Reference : https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Cryptotools {
    // Reference : https://docs.oracle.com/javase/7/docs/api/java/nio/file/Files.html#readAllBytes(java.nio.file.Path)
    private static boolean fileEquals(Path firstFile, Path secondFile) throws IOException {
        
            byte[] first = Files.readAllBytes(firstFile);
            byte[] second = Files.readAllBytes(secondFile);        
        return Arrays.equals(first, second);
    }

    public static void main(String[] args) throws Exception {
        File oneKbFile = new File("oneKbFile");
        File tenMbFile = new File("tenMbFile");
        File oneMbFile = new File("oneMbFile");
        System.out.println();
        long keyStart = System.nanoTime();
        KeyGenerator aesKey128 = KeyGenerator.getInstance("AES");
        aesKey128.init(128);
        SecretKey key = aesKey128.generateKey();
        long keyEnd = System.nanoTime();
        System.out.println(
                "Time it take to generate a new key(128 bit) " +
                        (keyEnd - keyStart) +
                        "\n"
        );


        Aes aes = new Aes();
        // Small File - 1KB
        // CBC MODE 128 bit key
        // Encrypting using 128 bit key for 1 Kb file
        long cbcEncryptStart = System.nanoTime();

        aes.encrypt(
                oneKbFile,
                new File("encrypt"),
                key,
                "AES/CBC/PKCS5Padding"
        );
        long cbcEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file in CBC mode " +
                        (cbcEncryptEnd - cbcEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt small file in CBC mode " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (cbcEncryptEnd - cbcEncryptStart) +
                        "\n"
        );

        // Decryption using 128 bit key in CBC mode for 1Kb file
        long cbcDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key,
                "AES/CBC/PKCS5Padding"
        );
        long cbcDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt small file in CBC mode " +
                        (cbcDecryptEnd - cbcDecryptStart)
        );

        System.out.println(
                "Speed per byte to decrypt small file in CBC mode " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (cbcDecryptEnd - cbcDecryptStart)
        );
        if (fileEquals(oneKbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) using CBC mode \n");

        // LARGE FILE - 10MB
        // Encrypting using 128 bit key for 10 Mb file
        cbcEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt"),
                key,
                "AES/CBC/PKCS5Padding"
        );
        cbcEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file in CBC mode " +
                        (cbcEncryptEnd - cbcEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file in CBC mode " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (cbcEncryptEnd - cbcEncryptStart) +
                        "\n"
        );

        // Decrypting using 128 bit key for 10 Mb file
        cbcDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key,
                "AES/CBC/PKCS5Padding"
        );
        cbcDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt large file in CBC mode " +
                        (cbcDecryptEnd - cbcDecryptStart)
        );
        System.out.println(
                "Speed per byte to decrypt large file in CBC mode " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (cbcDecryptEnd - cbcDecryptStart)
        );

        if (fileEquals(tenMbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (10 Mb File) using CBC mode \n");

        // SMALL FILE - 1KB
        // Encrypting one 1Kb file using 128 bit key in CTR mode
        long ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                oneKbFile,
                new File("encrypt"),
                key,
                "AES/CTR/NoPadding"
        );
        long ctrEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file in CTR mode " +
                        (ctrEncryptEnd - ctrEncryptStart)
        );

        System.out.println(
                "Speed per byte to encrypt small file in CTR mode " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (ctrEncryptEnd - ctrEncryptStart) +
                        "\n"
        );

        // Decrypting one 1Kb file using 128 bit key in CTR mode
        long ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key,
                "AES/CTR/NoPadding"
        );
        long ctrDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt small file in CTR mode " +
                        (ctrDecryptEnd - ctrDecryptStart)
        );
        System.out.println(
                "Speed per byte to decrypt small file in CTR mode " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (ctrDecryptEnd - ctrDecryptStart)
        );
        if (fileEquals(oneKbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) using CTR mode \n");
        // LARGE FILE - 10MB

        // Encrypting one 10Mb file using 128 bit key in CTR mode
        ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt"),
                key,
                "AES/CTR/NoPadding"
        );
        ctrEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file in CTR mode " +
                        (ctrEncryptEnd - ctrEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file in CTR mode " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (ctrEncryptEnd - ctrEncryptStart) +
                        "\n"
        );

        // Decrypting 10 Mb file in CTR mode using 128 bit AES key
        ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key,
                "AES/CTR/NoPadding"
        );
        ctrDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt large file in CTR mode " +
                        (ctrDecryptEnd - ctrDecryptStart)
        );
        System.out.println(
                "Speed per byte to decrypt large file in CTR mode " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (ctrDecryptEnd - ctrDecryptStart)
        );
        if (fileEquals(tenMbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (10 Mb File) using CTR mode \n");
        // CTR MODE

        // 256 BIT KEY GENERATION

        keyStart = System.nanoTime();
        KeyGenerator aesKey256 = KeyGenerator.getInstance("AES");
        aesKey256.init(256);
        SecretKey key256 = aesKey256.generateKey();
        keyEnd = System.nanoTime();
        System.out.println(
                "Time it take to generate a new key(256 bit) " +
                        (keyEnd - keyStart) +
                        "\n"
        );
        // Small File - 1Kb
        // Encrypt
        ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                oneKbFile,
                new File("encrypt"),
                key256,
                "AES/CTR/NoPadding"
        );
        ctrEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file in CTR mode using 256 bit key " +
                        (ctrEncryptEnd - ctrEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt small file in CTR mode using 256 bit key " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (ctrEncryptEnd - ctrEncryptStart) +
                        "\n"
        );

        // Decrypt
        ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key256,
                "AES/CTR/NoPadding"
        );
        ctrDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt small file in CTR mode using 256 bit key " +
                        (ctrDecryptEnd - ctrDecryptStart)
        );
        System.out.println(
                "Speed per byte to decrypt small file in CTR mode using 256 bit key " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (ctrDecryptEnd - ctrDecryptStart)
        );

        if (fileEquals(oneKbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) in CTR mode using 256 bit key \n");
        // Large File 10MB
        // Encrypt
        ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt"),
                key256,
                "AES/CTR/NoPadding"
        );
        ctrEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file in CTR mode using 256 bit key " +
                        (ctrEncryptEnd - ctrEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file in CTR mode using 256 bit key " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (ctrEncryptEnd - ctrEncryptStart) +
                        "\n"
        );
        // Decrypt
        ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt"),
                new File("decrypt"),
                key256,
                "AES/CTR/NoPadding"
        );
        ctrDecryptEnd = System.nanoTime();
        System.out.println(
                "Total time to decrypt large file in CTR mode using 256 bit key " +
                        (ctrDecryptEnd - ctrDecryptStart)
        );
        System.out.println(
                "Speed per byte to decrypt large file in CTR mode using 256 bit key " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
                                (ctrDecryptEnd - ctrDecryptStart)
        );

        if (fileEquals(tenMbFile.toPath(), new File("decrypt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (10 Mb File) in CTR mode using 256 bit key \n");

        //RSA key generation
        long rasKeyStart = System.nanoTime();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        long rasKeyEnd = System.nanoTime();

        System.out.println(
                "Time it take to generate a new rsa key pair " +
                        (rasKeyEnd - rasKeyStart) +
                        "\n"
        );

        Rsa rsa = new Rsa();
        long rsaEncryptStart = System.nanoTime();
        rsa.encrypt(new File("oneKbFile-rsa"), new File("encrypt"), publicKey);
        long rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file using RSA key " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt small file using RSA key " +
                        ((int) (new File("oneKbFile-rsa").length() * Math.pow(10, 9))) /
                                (rsaEncryptEnd - rsaEncryptStart) +
                        "\n"
        );

        

        rsaEncryptStart = System.nanoTime();
        rsa.encrypt(oneMbFile, new File("encrypt"), publicKey);
        rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file using RSA key " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file using RSA key " +
                        ((int) (oneMbFile.length() * Math.pow(10, 9))) /
                                (rsaEncryptEnd - rsaEncryptStart) +
                        "\n"
        );

        rasKeyStart = System.nanoTime();
        KeyPairGenerator generator3072 = KeyPairGenerator.getInstance("RSA");
        generator3072.initialize(3072);
        KeyPair pair3072 = generator.generateKeyPair();
        PrivateKey privateKey3072 = pair3072.getPrivate();
        PublicKey publicKey3072 = pair.getPublic();
        rasKeyEnd = System.nanoTime();

        System.out.println(
                "Time it take to generate a new rsa key pair of size 3072 bit " +
                        (rasKeyEnd - rasKeyStart) +
                        "\n"
        );

        rsaEncryptStart = System.nanoTime();
        rsa.encrypt(new File("oneKbFile-rsa"), new File("encrypt"), publicKey3072);
        rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file using RSA key of size 3072 bit " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt small file using RSA key of size 3072 bit " +
                        ((int) (new File("oneKbFile-rsa").length() * Math.pow(10, 9))) /
                                (rsaEncryptEnd - rsaEncryptStart) +
                        "\n"
        );

        

        rsaEncryptStart = System.nanoTime();
        rsa.encrypt(oneMbFile, new File("encrypt"), publicKey3072);
        rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file using RSA key of size 3072 bit " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file using RSA key of size 3072 bit " +
                        ((int) (oneMbFile.length() * Math.pow(10, 9))) /
                                (rsaEncryptEnd - rsaEncryptStart) +
                        "\n"
        );
        // Calculating Hash of Files
        // Reference:
        // https://docs.oracle.com/javase/9/security/java-cryptography-architecture-jca-reference-guide.htm#JSSEC-GUID-FB0090CA-2BCC-4D2C-BD2F-6F0A97197BD7
        ShaHash sha = new ShaHash();

        // Hasing using SHA-256
        long hashStart = System.nanoTime();
        sha.hashing("SHA-256", MessageDigest.getInstance("SHA-256"), oneKbFile);
        long hashEnd = System.nanoTime();
        System.out.println(
                "SHA-256 - Hashing time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart)
        );
        System.out.println(
                "SHA-256 - Hashing per byte time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart) /
                                oneKbFile.length() +
                        "\n"
        );

        hashStart = System.nanoTime();
        sha.hashing("SHA-256", MessageDigest.getInstance("SHA-256"), tenMbFile);
        hashEnd = System.nanoTime();

        System.out.println(
                "SHA-256 - Hashing time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart)
        );
        System.out.println(
                "SHA-256 - Hashing per byte time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart) /
                                tenMbFile.length() +
                        "\n"
        );
        // Hasing using SHA-512
        hashStart = System.nanoTime();
        sha.hashing("SHA-512", MessageDigest.getInstance("SHA-512"), oneKbFile);
        hashEnd = System.nanoTime();
        System.out.println(
                "SHA-512 - Hashing time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart)
        );
        System.out.println(
                "SHA-512 - Hashing per byte time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart) /
                                oneKbFile.length() +
                        "\n"
        );

        hashStart = System.nanoTime();
        sha.hashing("SHA-512", MessageDigest.getInstance("SHA-512"), tenMbFile);
        hashEnd = System.nanoTime();

        System.out.println(
                "SHA-512 - Hashing time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart)
        );

        System.out.println(
                "SHA-512 - Hashing per byte time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart) /
                                tenMbFile.length() +
                        "\n"
        );

        // Hasing using SHA3-256
        hashStart = System.nanoTime();
        sha.hashing("SHA-512", MessageDigest.getInstance("SHA3-256"), oneKbFile);
        hashEnd = System.nanoTime();
        System.out.println(
                "SHA3-256 - Hashing time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart)
        );
        System.out.println(
                "SHA3-256 - Hashing per byte time in nanoseconds - 1Kb File " +
                        (hashEnd - hashStart) /
                                oneKbFile.length() +
                        "\n"
        );
        hashStart = System.nanoTime();
        sha.hashing("SHA3-256", MessageDigest.getInstance("SHA3-256"), tenMbFile);
        hashEnd = System.nanoTime();

        System.out.println(
                "SHA3-256 - Hashing time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart)
        );
        System.out.println(
                "SHA3-256 - Hashing per byte time in nanoseconds - 10Mb File " +
                        (hashEnd - hashStart) /
                                tenMbFile.length() +
                        "\n"
        );

        long dsaStart = System.nanoTime();
        KeyPairGenerator dsaKey = KeyPairGenerator.getInstance("DSA");
        dsaKey.initialize(1024);
        KeyPair keyPair = dsaKey.generateKeyPair();
        PrivateKey dsaPrivateKey = keyPair.getPrivate();
        PublicKey dsaPublicKey = keyPair.getPublic();
        long dsaEnd = System.nanoTime();
        System.out.println(
                "Time it take to generate a new dsa key " +
                        (dsaEnd - dsaStart) +
                        "\n"
        );
        
        Dsa dsa = new Dsa();
        long dsaSignStart = System.nanoTime();
        dsa.dsaSign(oneKbFile,dsaPrivateKey);
        long dsaSignEnd = System.nanoTime();

        System.out.println(
                "Time it take to sign the file 1Kb " +
                        (dsaSignEnd - dsaSignStart)
        );

        System.out.println(
                "Time it take to sign the file 1Kb per byte " +
                        (dsaSignEnd - dsaSignStart)/oneKbFile.length()+"\n"
        );

        dsaSignStart = System.nanoTime();
        dsa.dsaSign(tenMbFile,dsaPrivateKey);
        dsaSignEnd = System.nanoTime();

        System.out.println(
                "Time it take to sign the file 10 Mb " +
                        (dsaSignEnd - dsaSignStart)
        );

        System.out.println(
                "Time it take to sign the file 10 Mb per byte " +
                        (dsaSignEnd - dsaSignStart)/tenMbFile.length()+"\n"
        );


        long dsaVerifyStart = System.nanoTime();
        dsa.dsaVerify(new File("signedFile"),dsaPublicKey);
        long dsaVerifyEnd = System.nanoTime();

        System.out.println(
                "Time it take to verify the file 1Kb " +
                        (dsaVerifyEnd - dsaVerifyStart)
        );

        System.out.println(
                "Time it take to verify the file 1Kb per byte " +
                        (dsaVerifyEnd - dsaVerifyStart)/oneKbFile.length()+"\n"
        );

        dsaVerifyStart = System.nanoTime();
        dsa.dsaVerify(new File("signedFile"),dsaPublicKey);
        dsaVerifyEnd = System.nanoTime();

        System.out.println(
                "Time it take to verify the file 10 Mb " +
                        (dsaVerifyEnd - dsaVerifyStart)
        );

        System.out.println(
                "Time it take to verify the file 10 Mb per byte " +
                        (dsaVerifyEnd - dsaVerifyStart)/tenMbFile.length()+"\n"
        );

        Files.deleteIfExists(Paths.get("encrypt"));
        Files.deleteIfExists(Paths.get("decrypt"));
        Files.deleteIfExists(Paths.get("Cryptotools.class"));
        Files.deleteIfExists(Paths.get("Aes.class"));
        Files.deleteIfExists(Paths.get("Rsa.class"));
        Files.deleteIfExists(Paths.get("ShaHash.class"));
        Files.deleteIfExists(Paths.get("signedFile"));
    }
}
