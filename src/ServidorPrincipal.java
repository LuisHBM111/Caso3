import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ServidorPrincipal {
	
	private int puerto;
	static Map<Integer, Servicio> tablaServicios;
	private PrivateKey llavePrivadaRSA;
	public PublicKey llavePublicaRSA;
	public PublicKey llavePublicaCliente;
	
	public ServidorPrincipal(int puerto) {
		
        this.puerto = puerto;
        
    }

	public static void main(String[] args) throws IOException {
		
		KeyPair keyPair = null;
		int puerto = 1234;
		
		try {
			
			keyPair = Criptografia.generarLlavesRSA();
			
		} catch (Exception e) {
			
		System.out.println("No se pudo generar la llave RSA");
		e.printStackTrace();
		
		}

		ServidorPrincipal servidor = new ServidorPrincipal(puerto);

		servidor.cargarServicios();
		servidor.cargarLLaves(keyPair);

		Socket socket = null;
		InputStreamReader inputStreamReader = null;
		OutputStreamWriter outputStreamWriter = null;
		BufferedReader bufferedReader = null;
		BufferedWriter bufferedWriter = null;
		ServerSocket serverSocket = null;
		
		serverSocket = new ServerSocket(servidor.puerto);
		
		String serviciosList = new String();
		for (Servicio servicio : tablaServicios.values()) {
			serviciosList = serviciosList + " " + servicio.getId() + " - " + servicio.getNombre();
		}
		
		while(true) {
			
			try {
				
				socket = serverSocket.accept();
				
				inputStreamReader = new InputStreamReader(socket.getInputStream());
				outputStreamWriter = new OutputStreamWriter(socket.getOutputStream());
				
				bufferedReader = new BufferedReader(inputStreamReader);
				bufferedWriter = new BufferedWriter(outputStreamWriter);
				
				while(true) {
					
					String msgFromClient = bufferedReader.readLine();
					
					System.out.println("Cliente: " + msgFromClient);
					
					if(msgFromClient.equalsIgnoreCase("SERVICIOS")) {
						bufferedWriter.write(serviciosList.toString() + " || ESCOGE UN SERVICIO CON SU ID");
						bufferedWriter.newLine();
						bufferedWriter.flush();
						String msgFromClient2 = bufferedReader.readLine();
						if(msgFromClient2.equalsIgnoreCase("1")) {
							bufferedWriter.write("PUERTO: " + "5001");
							bufferedWriter.newLine();
							bufferedWriter.flush();
						}else if(msgFromClient.equalsIgnoreCase("2")) {
							bufferedWriter.write("PUERTO: " + "5002");
							bufferedWriter.newLine();
							bufferedWriter.flush();
						}else if(msgFromClient.equalsIgnoreCase("3")) {
							bufferedWriter.write("PUERTO: " + "5003");
							bufferedWriter.newLine();
							bufferedWriter.flush();
						}else {
							bufferedWriter.write("TENIAS QUE ESCRIBIR ´1´ O ´2´ O ´3´");
							bufferedWriter.newLine();
							bufferedWriter.flush();
						}
					}	
					
					bufferedWriter.write("Mensaje recibido");
					bufferedWriter.newLine();
					bufferedWriter.flush();
					
					if(msgFromClient.equalsIgnoreCase("END"))break;
					
				}
				
				socket.close();
				inputStreamReader.close();
				outputStreamWriter.close();
				bufferedReader.close();
				bufferedWriter.close();
				
			}catch (IOException e) {
				e.printStackTrace();
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
