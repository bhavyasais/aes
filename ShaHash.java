import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ShaHash {

  public void hashing(String hash, MessageDigest md, File input)
    throws NoSuchAlgorithmException, IOException {
    FileInputStream inputStream = new FileInputStream(input);
    //Reference: https://docs.oracle.com/javase/7/docs/api/java/security/MessageDigest.html#update(byte[])
    byte[] buffer = new byte[120];
    int i = inputStream.read(buffer);
    while (i != -1) {
      md.update(buffer);
      i = inputStream.read(buffer);
    }
    inputStream.close();
  }
}
