package org.example;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws Exception {
        System.out.println("Hello world!");
        Scanner scanner=new Scanner(System.in);
        while(true){
            System.out.println("Select an option");
            System.out.println("1.CSR Generate");
            System.out.println("2.Certificate Parser");
            System.out.println("3.generate Self-signed Certificate and wrap in CMS format");
            System.out.println("4.Hybrid Cryptosystem from sender and reeiver");
            System.out.println("5.Exit");
            int choice=scanner.nextInt();
            scanner.nextLine();

            switch (choice)
            {
                case 1:
                    System.out.println("Generating CSR....");
                    CSRGenerator.generateCSR();
                    break;

                case 2:
                    System.out.println("Parsing...");
                    CSRParsing.parseCSR();

                    break;
                case 3:
                    System.out.print("generate signed Certificate in CMS format and verify ");
                    try {

                        System.out.println("Enter Common Name (CN): ");
                        String cn = scanner.nextLine();
                        // Rest of the code to get distinguished name (DN) details
                        String ou = "OU";
                        String o = "O";
                        String l = "L";
                        String st = "ST";
                        String c = "C";
                        String distinguishedName = String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", cn, ou, o, l, st, c);
                        KeyPair keyPair = SelfSignedCertificateGenerator.generateKeyPair("RSA");
                        X509Certificate certificate = SelfSignedCertificateGenerator.generateSelfSignedCertificate(keyPair, distinguishedName, "SHA256withRSA");

                        // Sign data
                        byte[] dataToSign = "Data to be signed.".getBytes();
                        System.out.println("Data to sign:"+dataToSign);
                        byte[] signedData = CMSDataSignerVerifier.signData(dataToSign, certificate, keyPair.getPrivate());
                        System.out.println("Data signed");
                        System.out.println("Verifying...");
                        // Optionally, write the signed data to a file
                        CMSDataSignerVerifier.saveToFile(signedData, cn + "_signedData.p7b");

                        // Verify signature
                        boolean isVerified = CMSDataSignerVerifier.verifySignedData(signedData);
                        System.out.println("Data verification result: " + (isVerified ? "passed" : "failed"));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                     break;
                case 4:
                System.out.println("Hybrid Cryptosystem from sender and receiver");
                // Generate the RSA key pair for the receiver (in practice, load this key pair instead)
                KeyPair keyPair = SelfSignedCertificateGenerator.generateKeyPair("RSA");
                PublicKey receiverPublicKey = keyPair.getPublic();
                PrivateKey receiverPrivateKey = keyPair.getPrivate();

                // Sender side: encrypt data
                byte[] data = "This is a secret message.".getBytes();
                byte[] encryptedData = HybridEncryptionSender.encryptData(data, receiverPublicKey);
                System.out.println("Data:"+ Arrays.toString(data));
                System.out.println("Encrypted Data"+ Arrays.toString(encryptedData));
                byte[] encryptedKey = HybridEncryptionSender.getEncryptedKey();
                System.out.println("Encrypted Key:"+ Arrays.toString(encryptedKey));
                byte[] iv = HybridEncryptionSender.getIv(); // Initialization Vector (IV)
                    System.out.println("Initialization vetor:"+ Arrays.toString(iv));

                // Receiver side: decrypt data
                byte[] decryptedData = HybridEncryptionReceiver.decryptData(encryptedData, encryptedKey, receiverPrivateKey, iv);
                System.out.println("Decrypted message: " + new String(decryptedData));
                break;
                case 5:
                    System.out.println("Exititng...");
                    break;
                default:
                    System.out.println("Enter a correct choice!");
            }
            System.out.println();

        }

    }
}