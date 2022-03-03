import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Aes {

    AlgorithmParameterSpec spec = new IvParameterSpec(new byte[16]);

    public void encrypt(File input, File output, SecretKey key, String instance)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        Cipher ecipher = Cipher.getInstance(instance);
        ecipher.init(Cipher.ENCRYPT_MODE, key, spec);
        InputStream inputStream = new FileInputStream(input);
        OutputStream outputStream = new FileOutputStream(output);
        outputStream = new CipherOutputStream(outputStream, ecipher);

        // Reference :
        // https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#CipherOutput
        byte[] buffer = new byte[12];
        int i = inputStream.read(buffer);
        while (i != -1) {
            outputStream.write(buffer, 0, i);
            i = inputStream.read(buffer);
        }
        outputStream.close();
        inputStream.close();
    }

    public void decrypt(File input, File output, SecretKey key, String instance)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
        Cipher dcipher = Cipher.getInstance(instance);
        dcipher.init(Cipher.DECRYPT_MODE, key, spec);
        InputStream inputStream = new FileInputStream(input);
        OutputStream outputStream = new FileOutputStream(output);
        inputStream = new CipherInputStream(inputStream, dcipher);
        // Reference :
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#CipherInput
        byte[] buffer = new byte[12];
        int i = inputStream.read(buffer);
        while (i != -1) {
            outputStream.write(buffer, 0, i);
            i = inputStream.read(buffer);
        }
        outputStream.close();
        inputStream.close();
    }
}
