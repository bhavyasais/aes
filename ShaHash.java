import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ShaHash {

  public void hashing(String hash, MessageDigest md, File in)
    throws NoSuchAlgorithmException, IOException {
    FileInputStream fis = new FileInputStream(in);
    byte[] dataBytes = new byte[1024];

    int nread = 0;
    while ((nread = fis.read(dataBytes)) != -1) {
      md.update(dataBytes, 0, nread);
    }
    fis.close();
  }
}
