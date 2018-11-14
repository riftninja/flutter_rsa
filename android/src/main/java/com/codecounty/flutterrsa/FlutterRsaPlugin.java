package com.codecounty.flutterrsa;

import org.json.JSONObject;
import java.security.KeyPair;

import io.flutter.plugin.common.MethodCall;
import io.flutter.plugin.common.MethodChannel;
import io.flutter.plugin.common.MethodChannel.MethodCallHandler;
import io.flutter.plugin.common.MethodChannel.Result;
import io.flutter.plugin.common.PluginRegistry.Registrar;

/** FlutterRsaPlugin */
public class FlutterRsaPlugin implements MethodCallHandler {

    /** Plugin registration. */
    public static void registerWith(Registrar registrar) {
        final MethodChannel channel = new MethodChannel(registrar.messenger(), "flutter_rsa");
        channel.setMethodCallHandler(new FlutterRsaPlugin());
    }

    @Override
    public void onMethodCall(MethodCall call, Result result) {
        switch (call.method) {
            case "generateKeyPairs":
                try {
                    KeyPair keyPair = RSACipher.generateKeyPair();
                    String pvk = RSACipher.privateKeyToString(keyPair.getPrivate());
                    String pbk = RSACipher.publicKeyToString(keyPair.getPublic());
                    JSONObject json = new JSONObject();
                    json.put("privateKey", pvk);
                    json.put("publicKey", pbk);
                    result.success(json.toString());
                } catch (Exception e) {
                    // e.printStackTrace();
                    result.error("Error Generating KeyPair", e.getLocalizedMessage(), e);
                }
                break;
            case "publicEncrypt":
                String transformation = call.argument("transformation");
                String plainMessage = call.argument("message");
                String publicKey = call.argument("publicKey");
                try {
                    result.success(RSACipher.publicEncrypt(plainMessage, publicKey, transformation));
                } catch (Exception e) {
                    // e.printStackTrace();
                    result.error("Error Encrypting Message", e.getLocalizedMessage(), e);
                }
                break;
            case "privateDecrypt":
                String transformation1 = call.argument("transformation");
                String encryptedMessage = call.argument("message");
                String privateKey = call.argument("privateKey");
                try {
                    result.success(RSACipher.privateDecrypt(encryptedMessage, privateKey, transformation1));
                } catch (Exception e) {
                    // e.printStackTrace();
                    result.error("Error Decrypting Message", e.getLocalizedMessage(), e);
                }
                break;
            default:
                result.notImplemented();
                break;
        }
    }
}
