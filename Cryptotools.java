// Reference : https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class Cryptotools {
    private static boolean fileEquals(Path firstFile, Path secondFile) {
        try {
            byte[] first = Files.readAllBytes(firstFile);
            byte[] second = Files.readAllBytes(secondFile);
            return Arrays.equals(first, second);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) throws Exception {
        File oneKbFile = new File("oneKbFile");
        File tenMbFile = new File("tenMbFile");
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
        // Encrypt
        long cbcEncryptStart = System.nanoTime();

        aes.encrypt(
                oneKbFile,
                new File("encrypt.txt"),
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

        // Decrypt
        long cbcDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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
        if (fileEquals(oneKbFile.toPath(), new File("decrypt.txt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) using CBC mode \n");

        // #### LARGE FILE - 1MB ###
        // Encrypt
        cbcEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt.txt"),
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

        // Decrypt
        cbcDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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

        if (fileEquals(tenMbFile.toPath(), new File("decrypt.txt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (10 Mb File) using CBC mode \n");
        // ########## CTR MODE 128 bit Key ###############

        // ### SMALL FILE - 1KB ###
        // Encrypt
        long ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                oneKbFile,
                new File("encrypt.txt"),
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

        // Decrypt
        long ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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
        if (fileEquals(oneKbFile.toPath(), new File("decrypt.txt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) using CTR mode \n");
        // ### LARGE FILE - 10MB ###

        // Encrypt
        ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt.txt"),
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

        // Decrypt
        ctrDecryptStart = System.nanoTime();
        aes.decrypt(
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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
        if (fileEquals(tenMbFile.toPath(), new File("decrypt.txt").toPath()))
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
                new File("encrypt.txt"),
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
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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

        if (fileEquals(oneKbFile.toPath(), new File("decrypt.txt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (1 Kb File) in CTR mode using 256 bit key \n");
        // Large File 10MB
        // Encrypt
        ctrEncryptStart = System.nanoTime();
        aes.encrypt(
                tenMbFile,
                new File("encrypt.txt"),
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
                new File("encrypt.txt"),
                new File("decrypt.txt"),
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

        if (fileEquals(tenMbFile.toPath(), new File("decrypt.txt").toPath()))
            System.out.println("The computed ciphertexts decrypt to the original data (10 Mb File) in CTR mode using 256 bit key \n");

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();
        Rsa rsa = new Rsa();
        // byte[] dataBytes = Files.readAllBytes(Paths.get("smallFile_1KB.txt"));
        long rsaEncryptStart = System.nanoTime();
        rsa.encrypt(oneKbFile, new File("encrypt.txt"), publicKey);
        long rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt small file using RSA key " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt small file using RSA key " +
                        ((int) (oneKbFile.length() * Math.pow(10, 9))) /
                                (rsaEncryptEnd - rsaEncryptStart) +
                        "\n"
        );

        rsaEncryptStart = System.nanoTime();
        rsa.encrypt(tenMbFile, new File("encrypt.txt"), publicKey);
        rsaEncryptEnd = System.nanoTime();
        System.out.println(
                "Total time to encrypt large file using RSA key " +
                        (rsaEncryptEnd - rsaEncryptStart)
        );
        System.out.println(
                "Speed per byte to encrypt large file using RSA key " +
                        ((int) (tenMbFile.length() * Math.pow(10, 9))) /
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

        Files.deleteIfExists(Paths.get("encrypt.txt"));
        Files.deleteIfExists(Paths.get("decrypt.txt"));
    }
}
