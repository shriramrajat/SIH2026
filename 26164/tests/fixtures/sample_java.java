package com.example.crypto;

import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class SampleCrypto {

    public void testSymmetric() throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    }

    public void testAsymmetric() throws Exception {
        KeyPairGenerator kpgRSA = KeyPairGenerator.getInstance("RSA");
        KeyPairGenerator kpgEC = KeyPairGenerator.getInstance("EC");
    }

    public void testHash() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
    }

    public void cleanBusinessLogic(int x) {
        int y = x * 10;
        System.out.println("Value: " + y);
    }
}
