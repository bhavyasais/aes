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

  byte[] iv = new byte[] {
    0x00,
    0x01,
    0x02,
    0x03,
    0x04,
    0x05,
    0x06,
    0x07,
    0x08,
    0x09,
    0x0a,
    0x0b,
    0x0c,
    0x0d,
    0x0e,
    0x0f,
  };
  AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);

  public void encrypt(File in, File out, SecretKey key, String instance)
    throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
    Cipher ecipher = Cipher.getInstance(instance);
    ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
    InputStream input = new FileInputStream(in);
    OutputStream output = new FileOutputStream(out);
    output = new CipherOutputStream(output, ecipher);

    // Reference :
    // https://docs.oracle.com/javase/7/docs/technotes/guides/security/crypto/CryptoSpec.html#CipherOutput
    byte[] buffer = new byte[12];
    int i = input.read(buffer);
    while (i != -1) {
      output.write(buffer, 0, i);
      i = input.read(buffer);
    }
    output.close();
    input.close();
  }

  public void decrypt(File in, File out, SecretKey key, String instance) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		Cipher dcipher = Cipher.getInstance(instance);
		dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
		InputStream input = new FileInputStream(in);
		OutputStream output = new FileOutputStream(out);
		input = new CipherInputStream(input, dcipher);
		// Reference :
		// https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#CipherInput
		byte[] buffer = new byte[12];
		int i = input.read(buffer);
		while (i != -1) {
			output.write(buffer, 0, i);
			i = input.read(buffer);
		}
		output.close();
		input.close();
	}
}
