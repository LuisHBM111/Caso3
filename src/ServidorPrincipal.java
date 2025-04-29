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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
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
        
        List<Thread> hilosClientes = new ArrayList<>();

        int cantidadClientesEsperados = 16;

        for (int i = 0; i < cantidadClientesEsperados; i++) {
            Socket socket = serverSocket.accept();
            Thread t = new Thread(() -> manejarCliente(socket));
            t.start();
            hilosClientes.add(t);
        }
        for (Thread t : hilosClientes) {
            t.join();
        }
        System.out.println("\n📊 Estadísticas totales de todos los clientes:");
        System.out.println("⏱ Tiempo total de firma: " + EstadisticasGlobales.totalTiempoFirma.get() + " ns");
        System.out.println("⏱ Tiempo total de cifrado: " + EstadisticasGlobales.totalTiempoCifrado.get() + " ns");
        System.out.println("⏱ Tiempo total de verificación HMAC: " + EstadisticasGlobales.totalTiempoVerificacionHMAC.get() + " ns");
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
    
    public static String mensajeCifrado(String mensaje, SecretKey llaveAES, SecretKey llaveHMAC) throws Exception {
        byte[] datosCifrados = cifrarAES(mensaje.getBytes(), llaveAES, iv);
        byte[] hmac = calcularHMAC(datosCifrados, llaveHMAC);
        byte[] mensajeFinal = concatenarBytes(datosCifrados, hmac);
        return Base64.getEncoder().encodeToString(mensajeFinal);
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
    
    public static void manejarCliente(Socket socket) {
        try (
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter bufferedWriter = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()))
        ) {
            System.out.println("Cliente conectado.");

            String mensajeInicial = "P: " + primo + " G: " + g + " LlavePublicaServidor: " + B +
                    " Iv: " + Base64.getEncoder().encodeToString(iv.getIV());

            String firma = firmarMensaje(mensajeInicial);
            bufferedWriter.write(mensajeInicial);
            bufferedWriter.newLine();
            bufferedWriter.write("Firma: " + firma);
            bufferedWriter.newLine();
            bufferedWriter.flush();

            // Recibir la llave pública del cliente
            String clientePublicKeyStr = bufferedReader.readLine();
            if (clientePublicKeyStr != null && clientePublicKeyStr.contains("LlavePublicaCliente:")) {
                clientePublicKeyStr = clientePublicKeyStr.replace("LlavePublicaCliente:", "").trim();
                BigInteger A_local = new BigInteger(clientePublicKeyStr);

                BigInteger s_local = A_local.modPow(b, primo);
                SecretKey[] llaves = generarLlaves(s_local.toByteArray());
                SecretKey llaveAES_local = llaves[0];
                SecretKey llaveHMAC_local = llaves[1];

                System.out.println("Llave pública del cliente: " + A_local);
                System.out.println("Llave privada generada: " + s_local);

                // Crear lista de servicios local
                StringBuilder serviciosList = new StringBuilder();
                for (Servicio servicio : tablaServicios.values()) {
                    serviciosList.append(servicio.getId()).append(" - ").append(servicio.getNombre()).append(" || ");
                }

                // Ciclo de interacción con el cliente
                while (true) {
                    String msgFromClient = bufferedReader.readLine();
                    if (msgFromClient == null) break;

                    if (msgFromClient.equalsIgnoreCase(mensajeCifrado("END", llaveAES_local, llaveHMAC_local))) {
                        System.out.println("Cliente pidió terminar.");
                        break;
                    }
                    
                    String mensajePlano = obtenerMensajeDescifrado(msgFromClient, llaveAES_local, llaveHMAC_local, iv);
                    if (mensajePlano != null && mensajePlano.equalsIgnoreCase("SERVICIOS")) {

                        long inicioCifrado = System.nanoTime();

                        byte[] datosCifradosServicios = cifrarAES(serviciosList.toString().getBytes(), llaveAES_local, iv);
                        byte[] hmacServicios = calcularHMAC(datosCifradosServicios, llaveHMAC_local);
                        byte[] mensajeFinal = concatenarBytes(datosCifradosServicios, hmacServicios);
                        String mensajeBase64 = Base64.getEncoder().encodeToString(mensajeFinal);

                        bufferedWriter.write(mensajeBase64);
                        bufferedWriter.newLine();
                        bufferedWriter.flush();

                        long finCifrado = System.nanoTime();
                        EstadisticasGlobales.totalTiempoCifrado.addAndGet(finCifrado - inicioCifrado);

                        String msgFromClient2 = bufferedReader.readLine();

                        long inicioVerificacion = System.nanoTime();
                        boolean valido = verificarMensajeConHMAC(msgFromClient2, llaveAES_local, llaveHMAC_local, iv);
                        long finVerificacion = System.nanoTime();

                        System.out.println("Verificación HMAC: " + (valido ? "Exitosa" : "Fallida"));
                        EstadisticasGlobales.totalTiempoVerificacionHMAC.addAndGet(finVerificacion - inicioVerificacion);

                        if (!valido) break;

                        String respuesta;
                        if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("1", llaveAES_local, llaveHMAC_local))) {
                            respuesta = mensajeCifrado("PUERTO: 5001 DIRECCION: localhost", llaveAES_local, llaveHMAC_local);
                        } else if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("2", llaveAES_local, llaveHMAC_local))) {
                            respuesta = mensajeCifrado("PUERTO: 5002 DIRECCION: localhost", llaveAES_local, llaveHMAC_local);
                        } else if (msgFromClient2.equalsIgnoreCase(mensajeCifrado("3", llaveAES_local, llaveHMAC_local))) {
                            respuesta = mensajeCifrado("PUERTO: 5003 DIRECCION: localhost", llaveAES_local, llaveHMAC_local);
                        } else {
                            respuesta = mensajeCifrado("-1 (TENÍAS QUE ESCRIBIR '1', '2' o '3')", llaveAES_local, llaveHMAC_local);
                        }

                        bufferedWriter.write(respuesta);
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                    } else {
                        String respuesta = mensajeCifrado("Comando no reconocido. Usa 'SERVICIOS' o 'END'.", llaveAES_local, llaveHMAC_local);
                        bufferedWriter.write(respuesta);
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("❌ Error al manejar cliente:");
            e.printStackTrace();
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static String obtenerMensajeDescifrado(String mensajeBase64, SecretKey aes, SecretKey hmac, IvParameterSpec iv) {
        try {
            if (!verificarMensajeConHMAC(mensajeBase64, aes, hmac, iv)) return null;
            byte[] mensajeBytes = Base64.getDecoder().decode(mensajeBase64);
            byte[] datosCifrados = Arrays.copyOfRange(mensajeBytes, 0, mensajeBytes.length - 32);
            return new String(descifrarAES(datosCifrados, aes, iv));
        } catch (Exception e) {
            return null;
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
