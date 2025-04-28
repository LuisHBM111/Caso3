import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ServidorPrincipal {
    
    private static BigInteger primo = null;
    private static BigInteger g = null;
    private static BigInteger b = null;
    private static BigInteger A = null;
    private static BigInteger B = null;
    private static BigInteger s = null;
    
    private int puerto;
    static Map<Integer, Servicio> tablaServicios;
    private PrivateKey llavePrivadaRSA;
    public PublicKey llavePublicaRSA;
    public PublicKey llavePublicaCliente;
    
    public ServidorPrincipal(int puerto) {
        this.puerto = puerto;
    }
    
    public static void main(String[] args) throws IOException {
        
        int puerto = 1234;
        ServidorPrincipal servidor = new ServidorPrincipal(puerto);

        servidor.cargarServicios();
        servidor.generarPrimo(1024);
        servidor.generarG();
        servidor.generarB();
        servidor.generarLLavePublica();
        
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
                
                bufferedWriter.write("P: " + primo + " G: " + g + " LlavePublicaServidor: " + B);
                bufferedWriter.newLine();
                bufferedWriter.flush();
                
                bufferedWriter.write("ENVIA TU LLAVE PUBLICA AHORA");
                bufferedWriter.newLine();
                bufferedWriter.flush();

                String clientePublicKeyStr = bufferedReader.readLine();
                System.out.println("DEBUG Recibido del cliente: " + clientePublicKeyStr);
                
                if (clientePublicKeyStr != null && clientePublicKeyStr.matches("\\d+")) {
                    A = new BigInteger(clientePublicKeyStr.trim());
                    generarLLavePrivada();
                    System.out.println("Llave pública del cliente A: " + A);
                    System.out.println("Llave secreta generada (s): " + s);
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
                    
                    if (msgFromClient.equalsIgnoreCase("END")) {
                        System.out.println("Cliente pidió terminar la conexión.");
                        break;
                    }
                    
                    if (msgFromClient.equalsIgnoreCase("SERVICIOS")) {
                        
                        bufferedWriter.write(serviciosList + " || ESCOGE UN SERVICIO CON SU ID");
                        bufferedWriter.newLine();
                        bufferedWriter.flush();
                        
                        String msgFromClient2 = bufferedReader.readLine();
                        
                        if (msgFromClient2.equalsIgnoreCase("1")) {
                            bufferedWriter.write("PUERTO: 5001 DIRECCION: localhost");
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        } else if (msgFromClient2.equalsIgnoreCase("2")) {
                            bufferedWriter.write("PUERTO: 5002 DIRECCION: localhost");
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        } else if (msgFromClient2.equalsIgnoreCase("3")) {
                            bufferedWriter.write("PUERTO: 5003 DIRECCION: localhost");
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        } else {
                            bufferedWriter.write("-1 (TENÍAS QUE ESCRIBIR '1' O '2' O '3')");
                            bufferedWriter.newLine();
                            bufferedWriter.flush();
                        }
                    } else {
                        bufferedWriter.write("Comando no reconocido. Escribe 'SERVICIOS' o 'END'.");
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
    
    private void cargarLLaves(KeyPair kp) {
        this.llavePrivadaRSA = kp.getPrivate();
        this.llavePublicaRSA = kp.getPublic();
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
    
    public static void atenderCliente(Socket clienteSocket) {
        
    }
    
    public static byte[] firmarDatos(byte[] datos) {
        return datos;
    }
    
    public static byte[] cifrarAES(byte[] datos, SecretKey llaveAES, IvParameterSpec iv) {
        return datos;
    }
    
    public static byte[] calcularHMAC(byte[] datos, SecretKey llaveHMAC) {
        return datos;
    }
}
