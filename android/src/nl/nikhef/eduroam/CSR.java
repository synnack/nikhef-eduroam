/* Copyright 2012 Wilco Baan Hofman */

package nl.nikhef.eduroam;


import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMWriter;

public class CSR {
	private static KeyPair pair;
	private static String csr;
	
	public CSR(String username) throws Exception {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
		kpGen.initialize(2048, new SecureRandom());
		pair = kpGen.generateKeyPair();
	    PKCS10CertificationRequest request = new PKCS10CertificationRequest("SHA256withRSA", new X500Principal(
	    		"CN="+username), pair.getPublic(), null, pair.getPrivate());
	    StringWriter stringWriter = new StringWriter();
		PEMWriter pemWrt = new PEMWriter(stringWriter);
		pemWrt.writeObject(request);
		pemWrt.close();
		csr = stringWriter.toString();
	}
	
	public final PrivateKey getPrivate() {
		return pair.getPrivate();
	}
	public final String getCSR() {
		return csr;
	}
}
