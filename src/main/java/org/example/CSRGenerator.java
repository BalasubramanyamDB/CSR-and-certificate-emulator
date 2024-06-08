package org.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Scanner;

public class CSRGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void generateCSR() throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Collect DN details from the user
        System.out.print("Enter Common Name (CN): ");
        String cn = scanner.nextLine();
        System.out.print("Enter Organization Unit (OU): ");
        String ou = scanner.nextLine();
        System.out.print("Enter Organization Name (O): ");
        String o = scanner.nextLine();
        System.out.print("Enter Locality Name (L): ");
        String l = scanner.nextLine();
        System.out.print("Enter State Name (ST): ");
        String st = scanner.nextLine();
        System.out.print("Enter Country (C): ");
        String c = scanner.nextLine();

        String distinguishedName = String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", cn, ou, o, l, st, c);

        // Choose key type
        System.out.print("Enter key type (RSA/ECC): ");
        String keyType = scanner.nextLine().toUpperCase();

        // Choose hashing algorithm
        System.out.print("Enter hashing algorithm (SHA256/SHA384): ");
        String hashAlgorithm = "SHA" + scanner.nextLine() + (keyType.equals("RSA") ? "withRSA" : "withECDSA");

        // Generate key pair based on user input
        KeyPair keyPair = generateKeyPair(keyType);

        // Generate the CSR
        X500Name x500Name = new X500Name(distinguishedName);
        PKCS10CertificationRequestBuilder csrBuilder = new PKCS10CertificationRequestBuilder(x500Name, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(hashAlgorithm);
        ContentSigner signer = csBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest csr = csrBuilder.build(signer);

        // Convert CSR to PEM format
        String pemCsr = "-----BEGIN CERTIFICATE REQUEST-----\n" +
                new String(org.bouncycastle.util.encoders.Base64.encode(csr.getEncoded())) +
                "\n-----END CERTIFICATE REQUEST-----";

        // Output PEM-formatted CSR to file
        try (FileOutputStream fos = new FileOutputStream(cn + ".csr.pem")) {
            fos.write(pemCsr.getBytes());
        }

        System.out.println("CSR generated successfully.");
    }

    private static KeyPair generateKeyPair(String keyType) throws Exception {
        KeyPairGenerator keyPairGenerator;
        switch (keyType) {
            case "RSA":
                keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537)));
                break;
            case "ECC":
                keyPairGenerator = KeyPairGenerator.getInstance("EC");
                keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
                break;
            default:
                throw new IllegalArgumentException("Unsupported key type: " + keyType);
        }
        return keyPairGenerator.generateKeyPair();
    }

    public static void main(String[] args) {
        try {
            generateCSR();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
