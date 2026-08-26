import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class CryptoMatrix {
    public void testSymmetric() throws Exception {
        Cipher c1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
        Cipher c2 = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher c3 = Cipher.getInstance("DES/ECB/NoPadding"); // extra
    }

    public void testAsymmetric() throws Exception {
        KeyPairGenerator kpg1 = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator kpg2 = KeyPairGenerator.getInstance("EC");
        KeyPairGenerator kpg3 = KeyPairGenerator.getInstance("DSA");
    }

    public void testHashing() throws Exception {
        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        MessageDigest md2 = MessageDigest.getInstance("MD5");
    }

    public void hardcodedSecrets() {
        String apiKey = "AIzaSyB-EXAMPLE-API-KEY-1234567890";
        String dbPass = "db_password_xyz";
    }
    
    // Commented out code
    // Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    // MessageDigest md = MessageDigest.getInstance("SHA-1");

    public void cryptoStrings() {
        System.out.println("Use Cipher.getInstance(\"AES/CBC/PKCS5Padding\") for encryption");
        String docs = "We support RSA and EC keys";
    }
}
