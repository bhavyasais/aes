import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

public class Rsa {

  public void encrypt(File input, File output, PublicKey publicKey)
    throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
    Cipher ecipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    ecipher.init(Cipher.ENCRYPT_MODE, publicKey);
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

  public void decrypt(File input, File output, PrivateKey privateKey)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
    Cipher dcipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
    dcipher.init(Cipher.DECRYPT_MODE, privateKey);
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
