package org.example;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

public class CMSDataSignerVerifier {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static byte[] signData(byte[] dataToSign, X509Certificate signingCertificate, PrivateKey signingKey) throws Exception {
        List<X509Certificate> certList = new ArrayList<>();
        certList.add(signingCertificate);

        Store<X509CertificateHolder> certs = new JcaCertStore(certList);

        CMSSignedDataGenerator signedDataGenerator = new CMSSignedDataGenerator();
        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(signingKey);

        signedDataGenerator.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()
                ).build(contentSigner, signingCertificate)
        );

        signedDataGenerator.addCertificates(certs);

        CMSTypedData cmsData = new CMSProcessableByteArray(dataToSign);
        CMSSignedData signedData = signedDataGenerator.generate(cmsData, true);

        return signedData.getEncoded();
    }

    public static boolean verifySignedData(byte[] signedData) throws CMSException, CertificateException, OperatorCreationException, IOException {
        CMSSignedData cmsSignedData = new CMSSignedData(signedData);
        Store<X509CertificateHolder> store = cmsSignedData.getCertificates();
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        for (SignerInformation signer : signers.getSigners()) {
            Collection<X509CertificateHolder> certCollection = store.getMatches(signer.getSID());
            Iterator<X509CertificateHolder> certIterator = certCollection.iterator();

            if (certIterator.hasNext()) {
                X509CertificateHolder certHolder = certIterator.next();
                X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

                return signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData));
            }
        }

        return false;
    }

    public static void saveToFile(byte[] data, String filename) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(filename)) {
            fos.write(data);
        }}
}
