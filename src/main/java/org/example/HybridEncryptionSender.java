package org.example;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.*;
import java.util.Base64;

public class HybridEncryptionSender {
    private static byte[] encryptedAesKey;
    private static byte[] iv;

    public static byte[] encryptData(byte[] data, PublicKey receiverPublicKey) throws GeneralSecurityException {
        //step 1: Generate AES KEY for Symmetric encryption
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey aesKey = keyGenerator.generateKey();

        //STEP 2: Encrypt this AES key using the receiver's RSA Public key

        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

        //step 3: encrypt the actual data using aes key...securely generate the IV
        iv = new byte[12]; // Use SecureRandom to generate
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmParameterSpec);

        //return the encrypted data
        return aesCipher.doFinal(data);
    }

    //return the encrypted AES KEY
    public static byte[] getEncryptedKey() {
        return encryptedAesKey;
    }

    //return the Init. vector
    public static byte[] getIv() {
        return iv;
}
}
