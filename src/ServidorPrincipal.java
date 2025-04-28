import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ServidorPrincipal {
	
	private int puerto;
	private Map<Integer, Servicio> tablaServicios;
	private PrivateKey llavePrivadaRSA;
	public PublicKey llavePublicaRSA;
	public PublicKey llavePublicaCliente;
	
	public ServidorPrincipal(int puerto) {
		
        this.puerto = puerto;
        
    }

	public static void main(String[] args) {
		
		KeyPair keyPair = null;
		
		try {
			keyPair = Criptografia.generarLlavesRSA();
		} catch (Exception e) {
			System.out.println("No se pudo generar la llave RSA");
			e.printStackTrace();
		}
		
		if (args.length != 1) {
            System.out.println("Uso: java ServidorPrincipal <puerto>");
            return;
        }

        int puerto = Integer.parseInt(args[0]);
        ServidorPrincipal servidor = new ServidorPrincipal(puerto);

        servidor.cargarServicios();
        servidor.cargarLLaves(keyPair);
        servidor.iniciarServidor();
        
        Cliente cliente = new Cliente(direccionServidor, puerto, llavePublicaRSA);

	}
	
	private void cargarServicios() {
		
		tablaServicios = new HashMap<>();

	    tablaServicios.put(1, new Servicio(1, "Consulta Estado de Vuelo", "192.168.1.2", 5001));
	    tablaServicios.put(2, new Servicio(2, "Disponibilidad de Vuelos", "192.168.1.3", 5002));
	    tablaServicios.put(3, new Servicio(3, "Costo de un Vuelo", "192.168.1.4", 5003));
	    
	}
	
	private void cargarLLaves(KeyPair kp) {
		
		this.llavePrivadaRSA = kp.getPrivate();
		this.llavePublicaRSA = kp.getPublic();
		
	}
	
	private void iniciarServidor() {
		
		try (ServerSocket serverSocket = new ServerSocket(puerto)) {
	        System.out.println("Servidor escuchando en el puerto " + puerto + "...");

	        while (true) {
	            Socket clienteSocket = serverSocket.accept();
	            System.out.println("Cliente conectado desde " + clienteSocket.getInetAddress().getHostAddress());

	            new Thread(() -> {
	                try {
	                    atenderCliente(clienteSocket);
	                } catch (Exception e) {
	                    e.printStackTrace();
	                }
	            }).start();
	        }
	    } catch (IOException e) {
	        System.out.println("Error iniciando el servidor: " + e.getMessage());
	        e.printStackTrace();
	    }
	    
	}

	public static void atenderCliente(Socket clienteSocket) {
		
		//aqui va la logica importante
		
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
