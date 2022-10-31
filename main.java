package hw4;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

public class main {

	static String rootCertPath = "G:\\YiJian\\Homework\\CMPSC444\\CAROOT.crt";
	public static boolean checkCert(String certFilePath, String email)  {
		// read cert 
		CertificateFactory fac = null;
		try {
			fac = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return false;
		}
		
		FileInputStream fs = null;
		try {
			fs = new FileInputStream(certFilePath);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			System.out.println("The certificate file does not exist ");
			return false;
		}

		X509Certificate root = null;
		try {
			root = (X509Certificate) fac.generateCertificate(new FileInputStream(rootCertPath));
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) fac.generateCertificate(fs);
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			System.out.println("A file is provided for the certificate file that is not a X.509 certificate ");
			return false;
		}
		
		/*
		 * blum3.cert - A file is provided for the certificate file that is not the correct certificate
		 */
		if (!cert.getSubjectX500Principal().toString().contains(email)) {
			System.out.println("A file is provided for the certificate file that is not the correct certificate ");
			return false;
		}
		
		/*
		 * blum1.cert - The period of validity has ended 
		 */
		try {
			cert.checkValidity();
		} catch (CertificateExpiredException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("The period of validity has ended ");
			return false;
		} catch (CertificateNotYetValidException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("The period of validity has not yet started ");
		}
		
		/*
		 * blum2.cert - The signature on the certificate is not valid 
		 */
		try {
			cert.verify(root.getPublicKey());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("The signature on the certificate is not valid ");
			return false;
		}
		
		return true;
	}

	public static void encrypt(String certFile, String email, String privKeyFile, String message) {
	}

	public static void decrypt(String certFile, String email, String privKeyFile, String wrappedKey, String IV,
			String ciphertext, String signature) {
	}

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		String certPath = "G:\\YiJian\\Homework\\CMPSC444\\HW4 blum\\blum3.cert";
		String email = "jjb24@cs.hbg.psu.edu";
		System.out.println(checkCert(certPath, email));
	}

}
