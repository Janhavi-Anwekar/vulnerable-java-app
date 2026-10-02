package demo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;

public class CryptoDemo {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rsaPair = rsa.generateKeyPair();

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(256);
        KeyPair ecPair = ec.generateKeyPair();
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(ecPair.getPrivate());

        KeyGenerator aes = KeyGenerator.getInstance("AES");
        aes.init(128);
        SecretKey key = aes.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha = MessageDigest.getInstance("SHA-384");
    }
}