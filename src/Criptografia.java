import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Criptografia {

	public static KeyPair generarLlavesRSA() {
		return null;
		
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
