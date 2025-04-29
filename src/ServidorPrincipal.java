import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
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
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class ServidorPrincipal {
    
    private static BigInteger primo = null;
    private static BigInteger g = null;
    private static BigInteger b = null;
    private static BigInteger A = null;
    private static BigInteger B = null;
    private static BigInteger s = null;
    
    private static SecretKey llaveAES = null;
    private static SecretKey llaveHMAC = null;
    private static IvParameterSpec iv;
    private static PrivateKey privateKeyServidor;
    
    private int puerto;
    static Map<Integer, Servicio> tablaServicios;
    public PublicKey llavePublicaCliente;
    
    public ServidorPrincipal(int puerto) {
        this.puerto = puerto;
    }
    
    public static void main(String[] args) throws Exception {
        
        int puerto = 1234;
        ServidorPrincipal servidor = new ServidorPrincipal(puerto);

        servidor.cargarServicios();
        servidor.generarPrimo(1024);
        servidor.generarG();
        servidor.generarB();
        servidor.generarLLavePublica();
        byte[] iv2 = new byte[16];
        new SecureRandom().nextBytes(iv2);
        IvParameterSpec ivSpec = new IvParameterSpec(iv2);
        iv = ivSpec;
        GeneradorLlavesRSA.generarLlaves("private_key.der", "public_key.der");
        privateKeyServidor = KeyUtils.cargarLlavePrivada("private_key.der");
        
        ServerSocket serverSocket = new ServerSocket(servidor.puerto);
        System.out.println("Servidor iniciado en el puerto " + puerto);

        String serviciosList = new String();
        for (Servicio servicio : tablaServicios.values()) {
            serviciosList += servicio.getId() + " - " + servicio.getNombre() + " || ";
        }
        
        while (true) {
            Socket socket = null;
            BufferedReader bufferedReader = null;
            BufferedWriter bufferedWriter = null;
            
            try {
                socket = serverSocket.accept();
                System.out.println("Cliente conectado.");
                
                bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
                
                String mensajeInicial = "P: " + primo + " G: " + g + " LlavePublicaServidor: " + B + " Iv: " + Base64.getEncoder().encodeToString(iv.getIV());
                
                String firma = firmarMensaje(mensajeInicial);
                
                bufferedWriter.write(mensajeInicial);
                bufferedWriter.newLine();
                bufferedWriter.write("Firma: " + firma);
                bufferedWriter.newLine();
                bufferedWriter.flush();

                String clientePublicKeyStr = bufferedReader.readLine();
                
                if (clientePublicKeyStr != null) {
                    if (clientePublicKeyStr.contains("LlavePublicaCliente:")) {
                        clientePublicKeyStr = clientePublicKeyStr.replace("LlavePublicaCliente:", "").trim();
                    }
                    A = new BigInteger(clientePublicKeyStr);
                    
                    generarLLavePrivada();
                    SecretKey[] llaves = generarLlaves(s.toByteArray());
                    SecretKey llaveAES = llaves[0];
                    SecretKey llaveHMAC = llaves[1];

                    System.out.println("Llave pública del cliente: " + A);
                    System.out.println("Llave privada generada: " + s);
                    
                } else {
                    System.err.println("Error en la llave pública recibida. Cerrando conexión.");
                    socket.close();
                    continue;
                }

                while (true) {
                    String msgFromClient = bufferedReader.readLine();
                    
                    if (msgFromClient == null) {
                        System.out.println("Cliente desconectado.");
                        break;
                    }
                    
                    System.out.println("Cliente: " + msgFromClient);
                    
                    if (msgFromClient.equalsIgnoreCase(mensajeCifrado("END"))) {
                        System.out.println("Cliente pidió terminar la conexión.");
                        break;
                    }
                    
                    if (msgFromClient.equalsIgnoreCase(mensajeCifrado("servicios"))) {
                    	
                    	long inicioCifrado = System.nanoTime();
                    	
                    	byte[] datosCifradosServicios = null;
                    	byte[] hmacServicios = null;
                    	
						try {
							datosCifradosServicios = cifrarAES(serviciosList.getBytes(), llaveAES, iv);
							hmacServicios = calcularHMAC(datosCifradosServicios, llaveHMAC);
						} catch (Exception e) {
							e.printStackTrace();
						}
						
						byte[] mensajeServicios = concatenarBytes(datosCifradosServicios, hmacServicios);

				        String mensajeBase64Servicios = Base64.getEncoder().encodeToString(mensajeServicios);

                        bufferedWriter.write(mensajeBase64Servicios);
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                        
                        long finCifrado = System.nanoTime();

                        long tiempoCifrado = finCifrado - inicioCifrado;
                        System.out.println("Tiempo para cifrar la tabla de servicios: " + tiempoCifrado + " nanosegundos");
                        
                        String msgFromClient2 = bufferedReader.readLine();
                        
                        long inicioVerificacion = System.nanoTime();
                        
                        boolean valido = verificarMensajeConHMAC(msgFromClient2, llaveAES, llaveHMAC, iv);
                        
                        if (!valido) {
                        	System.out.println("Error en la verificacion");
                        }else {
                        	System.out.println("Verficacion exitosa");
                        }
                        
                        long finVerificacion = System.nanoTime();
                        
                        long tiempoVerificacion = finVerificacion - inicioVerificacion;
                        System.out.println("Tiempo para verificar la consulta del cliente: " + tiempoVerificacion + " nanosegundos");
                        
                        if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("1"))) {
                        	
    				        try {
								bufferedWriter.write(mensajeCifrado("PUERTO: 5001 DIRECCION: localhost"));
							} catch (Exception e) {
								e.printStackTrace();
							}
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                            
                        } else if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("2"))) {
                        	
    				        try {
								bufferedWriter.write(mensajeCifrado("PUERTO: 5002 DIRECCION: localhost"));
							} catch (Exception e) {
								e.printStackTrace();
							}
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                            
                        } else if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("3"))) {
                        	
                            try {
								bufferedWriter.write(mensajeCifrado("PUERTO: 5003 DIRECCION: localhost"));
							} catch (Exception e) {
								e.printStackTrace();
							}
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                            
                        } else {
                        	try {
								bufferedWriter.write(mensajeCifrado("-1 (TENÍAS QUE ESCRIBIR '1' O '2' O '3')"));
							} catch (Exception e) {
								e.printStackTrace();
							}
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        }
                    } else {
                    	try {
							bufferedWriter.write(mensajeCifrado("Comando no reconocido. Escribe 'SERVICIOS' o 'END'."));
						} catch (Exception e) {
							e.printStackTrace();
						}
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                    }
                }
                
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (socket != null) socket.close();
                    if (bufferedReader != null) bufferedReader.close();
                    if (bufferedWriter != null) bufferedWriter.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    
    private void cargarServicios() {
        tablaServicios = new HashMap<>();
        tablaServicios.put(1, new Servicio(1, "Consulta Estado de Vuelo", "localhost", 5001));
        tablaServicios.put(2, new Servicio(2, "Disponibilidad de Vuelos", "localhost", 5002));
        tablaServicios.put(3, new Servicio(3, "Costo de un Vuelo", "localhost", 5003));
    }
    
    public static void generarPrimo(int bitLength) {
        Random rnd = new SecureRandom();
        primo = BigInteger.probablePrime(bitLength, rnd);
    }
    
    public static void generarG() {
        Random rng = new Random();
        int randomNumber = rng.nextInt(100) + 1;
        if (randomNumber < 50) {
            g = BigInteger.valueOf(2);
        } else {
            g = BigInteger.valueOf(5);
        }
    }
    
    public static void generarB() {
        Random rng = new Random();
        int randomNumber = rng.nextInt(100) + 1;
        b = BigInteger.valueOf(randomNumber);
    }
    
    public static void generarLLavePublica() {
        B = g.modPow(b, primo);
    }
    
    public static void generarLLavePrivada() {
        s = A.modPow(b, primo);
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
    
    public static boolean verificarMensajeConHMAC(String mensajeBase64, SecretKey llaveAES, SecretKey llaveHMAC, IvParameterSpec iv) {
        try {
            byte[] mensajeBytes = Base64.getDecoder().decode(mensajeBase64);

            int tamanoHMAC = 32;
            int tamanoDatos = mensajeBytes.length - tamanoHMAC;

            byte[] datosCifrados = Arrays.copyOfRange(mensajeBytes, 0, tamanoDatos);
            byte[] hmacRecibido = Arrays.copyOfRange(mensajeBytes, tamanoDatos, mensajeBytes.length);

            byte[] hmacCalculado = calcularHMAC(datosCifrados, llaveHMAC);

            if (!Arrays.equals(hmacCalculado, hmacRecibido)) {
                return false;
            }

            byte[] datosDescifrados = descifrarAES(datosCifrados, llaveAES, iv);
            String mensaje = new String(datosDescifrados);
            System.out.println("Mensaje descifrado y verificado: " + mensaje);

            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    
    public static IvParameterSpec generarIV() {
    	byte[] ivBytes = new byte[16];
    	SecureRandom random = new SecureRandom();
    	random.nextBytes(ivBytes);

    	IvParameterSpec iv = new IvParameterSpec(ivBytes);
    	
    	return iv;
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
    
    public static void cargarLlavePrivadaServidor(String rutaLlavePrivada) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(rutaLlavePrivada));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        privateKeyServidor = kf.generatePrivate(spec);
    }
    
    public static String firmarMensaje(String mensaje) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKeyServidor);
        privateSignature.update(mensaje.getBytes("UTF-8"));
        byte[] firma = privateSignature.sign();
        return Base64.getEncoder().encodeToString(firma);
    }
    
    public class GeneradorLlavesRSA {

        public static void generarLlaves(String rutaLlavePrivada, String rutaLlavePublica) {
            try {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(1024); // Tamaño de llave requerido
                KeyPair keyPair = keyPairGenerator.generateKeyPair();
                
                PrivateKey privateKey = keyPair.getPrivate();
                PublicKey publicKey = keyPair.getPublic();
                
                // Guardar la llave privada
                FileOutputStream fosPrivada = new FileOutputStream(rutaLlavePrivada);
                fosPrivada.write(privateKey.getEncoded());
                fosPrivada.close();
                
                // Guardar la llave pública
                FileOutputStream fosPublica = new FileOutputStream(rutaLlavePublica);
                fosPublica.write(publicKey.getEncoded());
                fosPublica.close();
                
                System.out.println("Llaves RSA generadas correctamente en:");
                System.out.println("Privada: " + rutaLlavePrivada);
                System.out.println("Pública: " + rutaLlavePublica);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
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
    
    public static void delegadosServidor(int puerto, String direccion) {

    }
}
