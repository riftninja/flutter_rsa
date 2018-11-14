package com.codecounty.flutterrsa;

import android.util.Base64;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Created by RiftNinja based on Awesometic's RSACipher
 * It's encrypt returns Base64 encoded, and also decrypt for Base64 encoded cipher
 * references:
 * - http://stackoverflow.com/questions/12471999/rsa-encryption-decryption-in-android
 * - https://www.masinamichele.it/2018/02/13/implementing-rsa-cryptography-in-kotlin/
 * - https://gist.github.com/awesometic/f1f52acf5904189f687724e42c461413
 */
public class RSACipher {

//    public PublicKey publicKey;
//    public PrivateKey privateKey;

    private final static String CRYPTO_METHOD = "RSA";
    private final static int CRYPTO_BITS = 2048;

//    public RSACipher()
//            throws NoSuchAlgorithmException,
//            NoSuchPaddingException,
//            InvalidKeyException,
//            IllegalBlockSizeException,
//            BadPaddingException {
//
//        KeyPair keyPair = generateKeyPair();
//        publicKey = keyPair.getPublic();
//        privateKey = keyPair.getPrivate();
//    }

    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(CRYPTO_METHOD);
        kpg.initialize(CRYPTO_BITS);
        return kpg.genKeyPair();
    }

    public static String publicEncrypt(String message, String publicKey, String transformation)
            throws NoSuchAlgorithmException,
            NoSuchPaddingException,
            InvalidKeyException,
            IllegalBlockSizeException,
            BadPaddingException {

        PublicKey rsaPublicKey = stringToPublicKey(publicKey);
        Cipher cipher = Cipher.getInstance(transformation);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());

        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT);
    }

    public static String privateDecrypt(String result, String privateKey, String transformation)
            throws NoSuchAlgorithmException,
            InvalidKeyException,
            NoSuchPaddingException,
            IllegalBlockSizeException,
            BadPaddingException {

        PrivateKey rsaPrivateKey = stringToPrivateKey(privateKey);
        Cipher cipher1 = Cipher.getInstance(transformation);
        cipher1.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] decryptedBytes = cipher1.doFinal(Base64.decode(result, Base64.DEFAULT));
        return new String(decryptedBytes);
    }

    private static PrivateKey stringToPrivateKey(String privateKeyString){
        try {
            if (privateKeyString.contains("-----BEGIN RSA PRIVATE KEY-----") || privateKeyString.contains("-----END RSA PRIVATE KEY-----"))
                privateKeyString = privateKeyString.replace("-----BEGIN RSA PRIVATE KEY-----", "").replace("-----END RSA PRIVATE KEY-----", "");
            byte[] keyBytes = Base64.decode(privateKeyString, Base64.DEFAULT);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePrivate(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // e.printStackTrace();
            return null;
        }
    }

    private static PublicKey stringToPublicKey(String publicKeyString){
        try {
            if (publicKeyString.contains("-----BEGIN PUBLIC KEY-----") || publicKeyString.contains("-----END PUBLIC KEY-----"))
                publicKeyString = publicKeyString.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
            byte[] keyBytes = Base64.decode(publicKeyString, Base64.DEFAULT);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            return keyFactory.generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // e.printStackTrace();
            return null;
        }
    }

    public static String privateKeyToString(PrivateKey privateKey){
        return Base64.encodeToString(privateKey.getEncoded(), Base64.DEFAULT);
    }

    public static String publicKeyToString(PublicKey publicKey){
        return Base64.encodeToString(publicKey.getEncoded(), Base64.DEFAULT);
    }
}