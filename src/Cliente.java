import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cliente {
	
	//Servidor
	private static String direccionServidor = "localhost";
	private static int puertoServidor = 1234;
	
	//Para leer mensajes
	static Socket socket = null;
	static InputStreamReader inputStreamReader = null;
	static OutputStreamWriter outputStreamWriter = null;
	static BufferedReader bufferedReader = null;
	static BufferedWriter bufferedWriter = null;
	
	//Criptografia
    private static BigInteger primo2 = null;
    private static BigInteger g2 = null;
    private static BigInteger a = null;
    private static BigInteger A = null;
    private static BigInteger B = null;
    private static BigInteger s = null;
    private static SecretKey llaveAES = null;
    private static SecretKey llaveHMAC = null;
    private static IvParameterSpec  iv;
    private static PublicKey publicKeyServidor;
	
	public static void main(String[] args) {
		
		try {
			cargarLlavePublicaServidor("public_key.der");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		Cliente cliente = new Cliente();
		
		try {
			
			Socket socket = new Socket(direccionServidor,puertoServidor);
			
			inputStreamReader = new InputStreamReader(socket.getInputStream());
			outputStreamWriter = new OutputStreamWriter(socket.getOutputStream());
			
			bufferedReader = new BufferedReader(inputStreamReader);
			bufferedWriter = new BufferedWriter(outputStreamWriter);
			
			Scanner scanner = new Scanner(System.in);
			
			recibirParametrosServidor(bufferedReader);
			
			cliente.generarA();
			cliente.generarLLavePublica();
			
			bufferedWriter.write("LlavePublicaCliente: " + A.toString());
			bufferedWriter.newLine();
			bufferedWriter.flush();
			
			cliente.generarLLavePrivada();
			
			SecretKey[] llaves = generarLlaves(s.toByteArray());
            SecretKey llaveAES = llaves[0];
            SecretKey llaveHMAC = llaves[1]; 
            System.out.println("Llave pública del cliente: " + A);
            System.out.println("Llave pública del servidor: " + B);
            System.out.println("Llave privada generada: " + s);
			
			while(true) {
				
				try {
					bufferedWriter.write(mensajeCifrado("servicios"));
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				bufferedWriter.newLine();
				bufferedWriter.flush();
				
				System.out.println("Servidor: " + bufferedReader.readLine());
				
				Random r = new Random();
		        int max=3,min=1;
		        int rng = r.nextInt(max - min + 1) + min;
		        
		        if(rng == 1) {
		        	try {
						bufferedWriter.write(mensajeCifrado("1"));
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					bufferedWriter.newLine();
					bufferedWriter.flush();
					
					System.out.println("Servidor: " + bufferedReader.readLine());
					
					break;
		        }
		        if(rng == 2) {
		        	try {
						bufferedWriter.write(mensajeCifrado("2"));
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					bufferedWriter.newLine();
					bufferedWriter.flush();
					
					System.out.println("Servidor: " + bufferedReader.readLine());
					
					break;
		        }
		        if(rng == 3) {
		        	try {
						bufferedWriter.write(mensajeCifrado("3"));
					} catch (Exception e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
					bufferedWriter.newLine();
					bufferedWriter.flush();
					
					System.out.println("Servidor: " + bufferedReader.readLine());
					
					break;
		        }
			}
			
		} catch (IOException e) {
			
			System.out.println("Error en el socket");
			e.printStackTrace();
			
		} finally {			
			try {
				if(socket != null) 
					socket.close();
				if(inputStreamReader != null) 
					inputStreamReader.close();
				if(outputStreamWriter != null) 
					outputStreamWriter.close();
				if(bufferedReader != null) 
					bufferedReader.close();
				if(bufferedWriter != null) 
					bufferedWriter.close();
			} catch (IOException e) {
				System.out.println("Error al cerrar socket");
				e.printStackTrace();
			}
			
		}
		
	}
    
	private static void recibirParametrosServidor(BufferedReader bufferedReader) throws IOException {
	    try {

	        String mensajeInicial = bufferedReader.readLine();
	        String firmaLinea = bufferedReader.readLine();

	        System.out.println("Servidor: " + mensajeInicial);

	        long inicioFirma = System.nanoTime();

	        if (firmaLinea.startsWith("Firma: ")) {
	            firmaLinea = firmaLinea.replace("Firma: ", "").trim();
	        }

	        if (!verificarFirma(mensajeInicial, firmaLinea)) {
	            System.out.println("⚠️ FIRMA NO VÁLIDA. Cerrando conexión.");
	            throw new IOException("Firma inválida del servidor.");
	        }

	        System.out.println("✅ Firma verificada correctamente.");
	        
	        long finFirma = System.nanoTime();

            long tiempoFirma = finFirma - inicioFirma;
            System.out.println("Tiempo para verificar Firma: " + tiempoFirma + " nanosegundos");

	        BigInteger primo = null;
	        BigInteger g = null;
	        BigInteger llavePublicaServidor = null;

	        String[] partes = mensajeInicial.split(" ");
	        for (int i = 0; i < partes.length; i++) {
	            if (partes[i].equals("P:")) {
	                primo = new BigInteger(partes[i + 1]);
	            } else if (partes[i].equals("G:")) {
	                g = new BigInteger(partes[i + 1]);
	            } else if (partes[i].equals("LlavePublicaServidor:")) {
	                llavePublicaServidor = new BigInteger(partes[i + 1]);
	            } else if (partes[i].equals("Iv:")) {
	                byte[] ivBytes = Base64.getDecoder().decode(partes[i + 1]);
	                iv = new IvParameterSpec(ivBytes);
	            }
	        }

	        g2 = g;
	        primo2 = primo;
	        B = llavePublicaServidor;

	    } catch (Exception e) {
	        System.out.println("❌ Error durante la verificación o lectura de parámetros.");
	        e.printStackTrace();
	        throw new IOException("Error crítico al recibir parámetros del servidor.");
	    }
	}


    public static void generarA() {
        Random rng = new Random();
        int randomNumber = rng.nextInt(100) + 1;
        a = BigInteger.valueOf(randomNumber);
    }
    
    public static void generarLLavePublica() {
        A = g2.modPow(a, primo2);
    }
    
    public static void generarLLavePrivada() {
        s = B.modPow(a, primo2);
    }
    
    public static SecretKey[] generarLlaves(byte[] datos) {
        try {
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] digest = sha512.digest(datos);

            byte[] claveCifrado = Arrays.copyOfRange(digest, 0, 32);
            byte[] claveHMAC = Arrays.copyOfRange(digest, 32, 64);

            SecretKey llaveAES2 = new SecretKeySpec(claveCifrado, "AES");

            SecretKey llaveHMAC2 = new SecretKeySpec(claveHMAC, "HmacSHA256");
            
            llaveAES = llaveAES2;

            llaveHMAC = llaveHMAC2;

            return new SecretKey[] { llaveAES2, llaveHMAC2 };
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    
    public static byte[] cifrarAES(byte[] datos, SecretKey llaveAES, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, llaveAES, iv);
        return cipher.doFinal(datos);
    }

    public static byte[] descifrarAES(byte[] datosCifrados, SecretKey llaveAES, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, llaveAES, iv);
        return cipher.doFinal(datosCifrados);
    }

    public static byte[] calcularHMAC(byte[] datos, SecretKey llaveHMAC) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(llaveHMAC);
        return mac.doFinal(datos);
    }
    
    public static byte[] concatenarBytes(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
    public static String mensajeCifrado(String mensaje) throws Exception {
    	
    	byte[] datosCifradosServicio = null;
    	byte[] hmacServicio = null;
    	
		try {
			datosCifradosServicio = cifrarAES(mensaje.getBytes(), llaveAES, iv);
			hmacServicio = calcularHMAC(datosCifradosServicio, llaveHMAC);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		byte[] mensajeServicio = concatenarBytes(datosCifradosServicio, hmacServicio);

        String mensajeBase64Servicio = Base64.getEncoder().encodeToString(mensajeServicio);
        
        return mensajeBase64Servicio;
    }
    
    public static void cargarLlavePublicaServidor(String rutaLlavePublica) throws Exception {
        publicKeyServidor = KeyUtils.cargarLlavePublica(rutaLlavePublica);
    }
    
    public class GeneradorLlavesRSAA {

        public static void generarLlaves(String rutaLlavePrivada, String rutaLlavePublica) {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024);
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();
                
                try (FileOutputStream fosPrivada = new FileOutputStream(rutaLlavePrivada)) {
                    fosPrivada.write(privateKey.getEncoded());
                }
                
                try (FileOutputStream fosPublica = new FileOutputStream(rutaLlavePublica)) {
                    fosPublica.write(publicKey.getEncoded());
                }
                
                System.out.println("Llaves RSA generadas correctamente:");
                System.out.println("- Privada: " + rutaLlavePrivada);
                System.out.println("- Pública: " + rutaLlavePublica);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    
    public static boolean verificarFirma(String mensaje, String firmaBase64) {
        try {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKeyServidor);
            publicSignature.update(mensaje.getBytes("UTF-8"));

            byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);
            return publicSignature.verify(firmaBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public class KeyUtils {

        public static PrivateKey cargarLlavePrivada(String rutaArchivo) throws Exception {
            byte[] keyBytes = Files.readAllBytes(Paths.get(rutaArchivo));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }

        public static PublicKey cargarLlavePublica(String rutaArchivo) throws Exception {
            byte[] keyBytes = Files.readAllBytes(Paths.get(rutaArchivo));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        }
    }
    
	public static void delegadosCliente(Socket socket) {
		//Diffie-Hellman, recibe tabla, elige servicio, envía id, etc.
		//mostrarServicios(Map<Integer, String> servicios)
		//seleccionarServicio(Set<Integer> serviciosIdsDisponibles)
	}
	
}
