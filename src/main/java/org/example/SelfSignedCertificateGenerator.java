package org.example;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

public class SelfSignedCertificateGenerator {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static X509Certificate generateSelfSignedCertificate(KeyPair keyPair, String distinguishedName, String hashAlgorithm) throws Exception {
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + (365 * 24 * 60 * 60 * 1000L)); // 1-year validity
        BigInteger serialNumber = new BigInteger(64, new SecureRandom()); // Random serial number

        X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(
                new X500Name(distinguishedName), // Issuer authority
                serialNumber,
                notBefore,
                notAfter,
                new X500Name(distinguishedName), // Subject
                keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder(hashAlgorithm)
                .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
                .getCertificate(certificateBuilder.build(contentSigner));
    }

    public static KeyPair generateKeyPair(String keyType) throws Exception {
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

    // Save the certificate to a file
    public static void saveCertificateToFile(X509Certificate cert, String filename) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(cert.getEncoded());
        }
    }

    // Main method for testing
    public static void main(String[] args) {
        try {
            String cn = "Example CN";
            String ou = "Example OU";
            String o = "Example O";
            String l = "Example L";
            String st = "Example ST";
            String c = "Example C";
            String distinguishedName = String.format("CN=%s, OU=%s, O=%s, L=%s, ST=%s, C=%s", cn, ou, o, l, st, c);

            KeyPair keyPair = generateKeyPair("RSA"); // Generate the RSA key pair
            X509Certificate certificate = generateSelfSignedCertificate(keyPair, distinguishedName, "SHA256withRSA");

            // Save the self-signed certificate to a file
            String filename = cn + "_selfsigned_cert.pem";
            saveCertificateToFile(certificate, filename);

            System.out.println("Self-signed certificate generated and saved to: " + filename);
        } catch (Exception e) {
            e.printStackTrace();

        }}
}
