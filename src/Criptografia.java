import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Criptografia {

	public static KeyPair generarLlavesRSA() throws Exception{
		
		KeyPair kpFinal = null;
		
		try {
			 
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
 
            kpg.initialize(1024);
 
            KeyPair kp = kpg.genKeyPair();
 
            System.out.println("Keypair : " + kp);
            
            kpFinal = kp;
        }
 
        catch (NoSuchAlgorithmException e) {
 
            System.out.println("Exception thrown : " + e);
        }
		
		return kpFinal;
		
	}
	
	public static void guardarLlavesEnArchivos(KeyPair keyPair) {
		
		try {
            
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();

            
            try (FileOutputStream fos = new FileOutputStream("keys/private_key_server.der")) {
                fos.write(privateKey.getEncoded());
            }

            
            try (FileOutputStream fos = new FileOutputStream("keys/public_key_server.der")) {
                fos.write(publicKey.getEncoded());
            }

            System.out.println("Llaves RSA guardadas exitosamente en 'keys/'");

        } catch (IOException e) {
            System.out.println("Error guardando las llaves: " + e.getMessage());
            e.printStackTrace();
        }
		
    }
	
	public static KeyPair generarLlavesDiffieHellman() {
		return null;
		
	}
	
	public static SecretKey generarLlaveAES(byte[] bytes) {
		return null;
		
	}
	
	public static IvParameterSpec generarIV() {
		return null;
		
	}
	
	public static byte[] cifrarAES(byte[] datos, SecretKey llaveAES, IvParameterSpec iv) {
		return null;
		
	}
	
	public static byte[] descifrarAES(byte[] datos, SecretKey llaveAES, IvParameterSpec iv) {
		return null;
		
	}
	
	public static byte[] firmarRSA(byte[] datos, PrivateKey privateKey) {
		return null;
		
	}
	
	public static boolean verificarFirmaRSA(byte[] datos, byte[] firma, PublicKey publicKey) {
		return false;
		
	}
	
	public static byte[] calcularHMAC(byte[] datos, SecretKey llaveHMAC) {
		return null;
		
	}
	
	public static boolean verificarHMAC(byte[] datos, byte[] hmac, SecretKey llaveHMAC) {
		return false;
		
	}
	
}
