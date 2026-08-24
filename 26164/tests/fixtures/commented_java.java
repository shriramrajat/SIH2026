package com.example.crypto;

import javax.crypto.Cipher;

public class CommentedJavaCrypto {
    public void testCrypto() throws Exception {
        // Real active cipher call
        Cipher c1 = Cipher.getInstance("AES/GCM/NoPadding");

        // Line comment false-positive
        // Cipher c2 = Cipher.getInstance("AES/CBC/PKCS5Padding");

        /*
         * Multi-line block comment false-positive
         * Cipher c3 = Cipher.getInstance("DES/ECB/PKCS5Padding");
         */

        /* Single-line block comment: Cipher c4 = Cipher.getInstance("RSA"); */
    }
}
