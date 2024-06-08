package org.example;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import java.io.FileReader;
import java.io.Reader;
import java.security.PublicKey;

public class CSRParsing {

    public static void main(String[] args) {
        String csrFilePath = "D:\\java\\hw\\certificate_signing_req\\c.csr.pem";
        parseCSR();
    }

    public static void parseCSR() {
        String csrFilePath="D:\\java\\hw\\certificate_signing_req\\common.csr.pem";
        try (Reader reader = new FileReader(csrFilePath)) {
            PEMParser pemParser = new PEMParser(reader);
            Object parsedObj = pemParser.readObject();

            if (parsedObj instanceof PKCS10CertificationRequest) {
                PKCS10CertificationRequest csr = (PKCS10CertificationRequest) parsedObj;
                System.out.println("Basic Fields:");
                printBasicFields(csr);

                System.out.println("\nExtensions:");
                printExtensions(csr); // Note: CSRs may not necessarily contain extensions
            } else {
                System.out.println("Not a valid CSR file");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void printBasicFields(PKCS10CertificationRequest csr) throws Exception {
        X500Name subject = csr.getSubject();
        System.out.println("Subject: " + subject);

        SubjectPublicKeyInfo pkInfo = csr.getSubjectPublicKeyInfo();
        PublicKey pubKey = new JcaPEMKeyConverter().getPublicKey(pkInfo);
        System.out.println("Public Key: " + pubKey);
        System.out.println("Public Key Algorithm: " + pubKey.getAlgorithm());
        // You can add more analysis of the public key here if needed
    }

    private static void printExtensions(PKCS10CertificationRequest csr) {
        org.bouncycastle.asn1.pkcs.Attribute[] attributes = csr.getAttributes();

        for (Attribute attr : attributes) {
            System.out.println("Attribute OID: " + attr.getAttrType());
            // You may need to handle each type of attribute according to its specification
            // As attributes may contain various types of information including extensions
            // Here we just print out the value
            System.out.println("Attribute Value: " + attr.getAttrValues());

        }
    }
}