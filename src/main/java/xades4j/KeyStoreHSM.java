package xades4j;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import java.security.cert.X509Certificate;

import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumRSAPrivateKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.*;
import java.util.Collection;

public class KeyStoreHSM {
	private static Logger logger = LoggerFactory.getLogger(KeyStoreHSM.class);

	public CaviumRSAPrivateKey getPrivateKey(String alias)
			throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException,
			UnrecoverableKeyException {
		KeyStore keyStore = KeyStore.getInstance("Cavium");
		keyStore.load(null, null);
		Key key = null;
		// try {
			key = keyStore.getKey(alias, null);

			CaviumKey privatKey = (CaviumRSAPrivateKey) key;
			logger.debug("RSA key loaded, key Handler = {}", privatKey.getHandle());

		// } catch (UnrecoverableKeyException e) {
		// 	logger.error("Error getting privateKey from HSM {}", e.getMessage());
		// 	throw e;
		// }

		return (CaviumRSAPrivateKey) key;
	}

	public X509Certificate[] getCertificate(String certFileName) throws CertificateException {
		CertificateFactory certFactory;

		InputStream certEndEntity = 
		App.class.getClassLoader()
					.getResourceAsStream("certificate/" + certFileName);
		InputStream certIntermediateCA = 
					App.class.getClassLoader()
								.getResourceAsStream("certificate/CertificateChainOfINETCA.p7b" );
			
		Collection<X509Certificate> certificates = null;
		certFactory = CertificateFactory.getInstance("X.509");
		certificates = (Collection<X509Certificate>) certFactory.generateCertificates(certEndEntity);
		certificates.addAll((Collection<? extends X509Certificate>) certFactory.generateCertificates(certIntermediateCA));
		return certificates.toArray(new X509Certificate[0]);
	}
}
