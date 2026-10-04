package demo;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;

/**
 * Test fixture for ECDAT: a spread of cryptographic assets covering
 * quantum-vulnerable, classically weak, and quantum-safe usage.
 * It exists only to be scanned. It is not meant to be used for real security.
 */
public class QuantumRiskDemo {

    public static void main(String[] args) throws Exception {
        asymmetric();
        symmetric();
        hashing();
        macAndKdf();
        legacy();
    }

    // Public-key crypto: all broken by Shor's algorithm on a quantum computer.
    static void asymmetric() throws Exception {
        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(3072);
        KeyPair rsaPair = rsa.generateKeyPair();
        Signature rsaSig = Signature.getInstance("SHA256withRSA");
        rsaSig.initSign(rsaPair.getPrivate());
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(2048);
        KeyPair dsaPair = dsa.generateKeyPair();

        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");
        dh.initialize(2048);
        KeyPair dhPair = dh.generateKeyPair();

        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
        ec.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair ecPair = ec.generateKeyPair();
        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH");
        ecdh.init(ecPair.getPrivate());
        Signature ecdsa = Signature.getInstance("SHA384withECDSA");
        ecdsa.initSign(ecPair.getPrivate());

        KeyPairGenerator ed = KeyPairGenerator.getInstance("Ed25519");
        KeyPair edPair = ed.generateKeyPair();
        Signature edSig = Signature.getInstance("Ed25519");
        edSig.initSign(edPair.getPrivate());
    }

    // Symmetric crypto: Grover's algorithm halves effective key strength.
    static void symmetric() throws Exception {
        KeyGenerator aes256 = KeyGenerator.getInstance("AES");
        aes256.init(256);
        SecretKey key256 = aes256.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, key256, new GCMParameterSpec(128, iv));

        KeyGenerator aes128 = KeyGenerator.getInstance("AES");
        aes128.init(128);
        Cipher ecb = Cipher.getInstance("AES/ECB/PKCS5Padding"); // weak mode

        Cipher chacha = Cipher.getInstance("ChaCha20-Poly1305");
    }

    // Hash functions: MD5 and SHA-1 are classically broken.
    static void hashing() throws Exception {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        MessageDigest sha3 = MessageDigest.getInstance("SHA3-512");
    }

    // MAC, password-based key derivation, and a hardcoded key.
    static void macAndKdf() throws Exception {
        byte[] hardcoded = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
        SecretKeySpec hardcodedKey = new SecretKeySpec(hardcoded, "AES");

        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(hardcoded, "HmacSHA256"));

        SecretKeyFactory pbkdf2 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec("password".toCharArray(), new byte[16], 600000, 256);
        SecretKey derived = pbkdf2.generateSecret(spec);
    }

    // Deprecated ciphers that should be flagged as weak.
    static void legacy() throws Exception {
        KeyGenerator des = KeyGenerator.getInstance("DES");
        Cipher tripleDes = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        Cipher rc4 = Cipher.getInstance("RC4");
    }
}