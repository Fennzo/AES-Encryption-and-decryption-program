package hw4;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class main {

	// File path of CACert root certificate
	static String rootCertPath = "G:\\YiJian\\Homework\\CMPSC444\\CAROOT.crt";

	public static boolean checkCert(String certFilePath, String email) {
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
		 * blum3.cert - A file is provided for the certificate file that is not the
		 * correct certificate
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

	public static void encrypt(String certFilePath, String email, String privKeyFilePath, String message)
			throws NoSuchAlgorithmException {

		// Verify cert
		if (!checkCert(certFilePath, email))
			System.out.println("Certificate doesn't belong to owner");

		// Set up certificateFactory
		CertificateFactory fac = null;
		try {
			fac = CertificateFactory.getInstance("X509");
		} catch (CertificateException e) {
			e.printStackTrace();
		}

		// Ready cert
		FileInputStream fs = null;
		try {
			fs = new FileInputStream(certFilePath);
		} catch (FileNotFoundException e) {
			System.out.println("The certificate file does not exist ");
		}

		// Transform to x509
		X509Certificate myCert = null;
		try {
			myCert = (X509Certificate) fac.generateCertificate(new FileInputStream(certFilePath));
		} catch (CertificateException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// Generate AES key
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance("AES");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		keyGen.init(128);
		SecretKey aesKey = keyGen.generateKey();

		// Set up cipher
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Set up cipher with AES key
		try {
			cipher.init(Cipher.ENCRYPT_MODE, aesKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// IV
		String encodedIV = Base64.getEncoder().encodeToString(cipher.getIV());
		System.out.println("Encoded IV: " + encodedIV);
		
		// Encrypt message
		byte[] cipherText = null;
		try {
			cipherText = cipher.doFinal(message.getBytes("UTF-8"));
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// cipherText
		String encodedCipherText = Base64.getEncoder().encodeToString(cipherText);
		System.out.println("Encoded CipherText: " + encodedCipherText);
		
		// Create rsa cipher
		Cipher rsaCipher = null;
		try {
			rsaCipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// set up RSA cipher wrap mode with my certificate
		try {
			rsaCipher.init(Cipher.WRAP_MODE, myCert);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Wrap AES key
		String wrappedKey = null;
		try {
			wrappedKey = Base64.getEncoder().encodeToString(rsaCipher.wrap(aesKey));
		} catch (InvalidKeyException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IllegalBlockSizeException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		System.out.println("Wrapped key: " + wrappedKey);

		// Set up SHA-256 algo
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Apply SHA-256 algo to cipherText
		md.update(cipherText);

		RSAPrivateKey rsaPK = readPrivateKey(fs, privKeyFilePath);

		// Set up cipher to encrypt hashed cipherText using RSA with my private key
		try {
			rsaCipher.init(Cipher.ENCRYPT_MODE, rsaPK);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Encrypt the hashed cipherText with RSA
		String digitalSignature = null;
		try {
			digitalSignature = Base64.getEncoder().encodeToString(rsaCipher.doFinal(cipherText));
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("Digital signature: " + digitalSignature);

	}

	/*
	 * Convert .pem to RSAPrivatekey obj
	 */
	private static RSAPrivateKey readPrivateKey(FileInputStream fs, String privKeyFilePath)
			throws NoSuchAlgorithmException {
		
		byte[] encoded = null;
		try {
			encoded = Files.readAllBytes(Paths.get(privKeyFilePath));
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		try {
			return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("The private key file is not a PKCS8 private key file ");
		}
		return null;
	}

	public static void decrypt(String certFilePath, String email, String privKeyFilePath, String wrappedKey, String IV,
			String ciphertext, String signature) throws NoSuchAlgorithmException {

		if (!checkCert(certFilePath, email))
			System.out.println("Certificate doesn't belong to owner");

		// Obtain private key
		FileInputStream fs = null;
		try {
			fs = new FileInputStream(privKeyFilePath);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("The private key file does not exist ");
		}
		RSAPrivateKey rsaPrivateKey = readPrivateKey(fs, privKeyFilePath);

		// Set up cipher to unwrap
		Cipher rsaCipher = null;
		try {
			rsaCipher = Cipher.getInstance("RSA");
		} catch (NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (NoSuchPaddingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		try {
			rsaCipher.init(Cipher.UNWRAP_MODE, rsaPrivateKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Obtain AES key from unwrap
		SecretKey aesKey = null;
		try {
			aesKey = (SecretKey) rsaCipher.unwrap(Base64.getDecoder().decode(wrappedKey), "AES", Cipher.SECRET_KEY);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Get the IV
		IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(IV));

		// Set up the cipher - the encryption algorithm
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// Generate the ciphertext
		byte[] plaintext = null;
		try {
			plaintext = cipher.doFinal(Base64.getDecoder().decode(ciphertext));
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(plaintext);
        byte[] hash = md.digest();
        if (signature.equals(Base64.getEncoder().encodeToString(hash))) {
            try {
				System.out.println(new String(plaintext, "UTF-8"));
			} catch (UnsupportedEncodingException e) {
				e.printStackTrace();
			}
        }
        else {
            System.err.println("Message has been changed in transit");
        }
	}	

	public static void main(String[] args) throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		String certPath = "G:\\YiJian\\Homework\\CMPSC444\\yijianjin.cert";
		String email = "yijian36@gmail.com";
		String privateKeyPath = "G:\\YiJian\\Homework\\CMPSC444\\yj.priv";
		String message = "Jeremy Blum is GOAT";
		//System.out.println(checkCert(certPath, email));
		encrypt(certPath, email, privateKeyPath, message);
	}

}
