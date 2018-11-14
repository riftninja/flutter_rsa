import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';

class FlutterRsa {
    FlutterRsa(this.privateKey);
    final String privateKey;

    static const MethodChannel _channel = const MethodChannel('flutter_rsa');

    /// RSA Encrypt using public key
    ///
    /// Example Algorithms; RSA/ECB/OAEPWithSHA1AndMGF1Padding, RSA/ECB/PKCS1Padding, RSA/ECB/OAEPPadding
    ///
    /// reference: https://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#Cipher
    static Future<KeyPair> generateKeyPair({ String privateKey }) async {
        final String keys = await _channel.invokeMethod('generateKeyPairs');
        Map keyPair = json.decode(keys);
        return new KeyPair(keyPair['privateKey'], keyPair['publicKey']);
    }

    /// RSA Encrypt using public key
    ///
    /// Example Algorithms; RSA/ECB/OAEPWithSHA1AndMGF1Padding, RSA/ECB/PKCS1Padding, RSA/ECB/OAEPPadding
    ///
    /// reference: https://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#Cipher
    // todo change to publicEncrypt
    static Future<String> encrypt(String message, String publicKey, { transformation: 'RSA/ECB/OAEPWithSHA1AndMGF1Padding' }) async {
        final String encryptedMessage = await _channel.invokeMethod('publicEncrypt', {
            "message": message, "publicKey": publicKey, "transformation": transformation
        });
        return encryptedMessage;
    }

    /// RSA Encrypt using public key
    ///
    /// Example Algorithms; RSA/ECB/OAEPWithSHA1AndMGF1Padding, RSA/ECB/PKCS1Padding, RSA/ECB/OAEPPadding
    ///
    /// reference: https://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html#Cipher
    // todo change to privateDecrypt
    static Future<String> decrypt(String encryptedMessage, String privateKey, { transformation: 'RSA/ECB/OAEPPadding' }) async {
        print(transformation);
        final String decryptedMessage = await _channel.invokeMethod('privateDecrypt', {
            "message": encryptedMessage, "privateKey": privateKey, "transformation": transformation
        });
        return decryptedMessage;
    }
}

class KeyPair{
    KeyPair(this.privateKey, this.publicKey);
    final String privateKey;
    final String publicKey;
}