package org.example;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Arrays;

public class HybridEncryptionReceiver {


    public static byte[] decryptData(byte[] encryptedData, byte[] encryptedKey, PrivateKey receiverPrivateKey, byte[] iv) throws GeneralSecurityException {
        //Decrypt the symm key
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] aesKey = rsaCipher.doFinal(encryptedKey);

        System.out.println("aes key from recv"+Arrays.toString(aesKey));
        Cipher aesCipher = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey originalKey = new SecretKeySpec(aesKey, 0, aesKey.length, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
        aesCipher.init(Cipher.DECRYPT_MODE, originalKey, gcmParameterSpec);
        System.out.println("AES Cipher"+aesCipher);
        return aesCipher.doFinal(encryptedData);
}
}