import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
public class Dsa {
    public static void main(String[] args) {

    }
    //References : https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html
    public void dsaSign(File input, PrivateKey dsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException, SignatureException {
        Signature dsaSignature = Signature.getInstance("DSA");
        dsaSignature.initSign(dsaPrivateKey);
        byte[] buffer = new byte[100];
        new FileInputStream(input).read(buffer);
        dsaSignature.update(buffer);
        byte[] signature = dsaSignature.sign();
        DataOutputStream outputStream = new DataOutputStream(new FileOutputStream("signedFile"));
        outputStream.write(signature);
    }

    public void dsaVerify(File input, PublicKey dsaPublicKey) throws NoSuchAlgorithmException, InvalidKeyException, FileNotFoundException, IOException, SignatureException {
        Signature dsaSign = Signature.getInstance("DSA");
        dsaSign.initVerify(dsaPublicKey);
        byte[] buffer = new byte[1024];
        new FileInputStream(input).read(buffer);
        byte[] verifiedArray = new byte[1024];
        new FileInputStream(input).read(verifiedArray);
        dsaSign.update(verifiedArray);

    }
}
