import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.PortUnreachableException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Scanner;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

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
	private PrivateKey llavePrivadaCliente;
	private PrivateKey llavePublicaCliente;
	public PublicKey llavePublicaServidor;
	
	public static void main(String[] args) {
		
		try {
			
			Socket socket = new Socket(direccionServidor,puertoServidor);
			
			inputStreamReader = new InputStreamReader(socket.getInputStream());
			outputStreamWriter = new OutputStreamWriter(socket.getOutputStream());
			
			bufferedReader = new BufferedReader(inputStreamReader);
			bufferedWriter = new BufferedWriter(outputStreamWriter);
			
			Scanner scanner = new Scanner(System.in);
			
			while(true) {
				
				String msgToSend = scanner.nextLine();
				
				bufferedWriter.write(msgToSend);
				bufferedWriter.newLine();
				bufferedWriter.flush();
				
				System.out.println("Server: " + bufferedReader.readLine());
				
				if(msgToSend.equalsIgnoreCase("END")) break;	
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
	
	public Cliente(String direccionServidor, int puertoServidor, PublicKey llavePublicaServidor) {
		
		super();
		this.direccionServidor = direccionServidor;
		this.puertoServidor = puertoServidor;
		this.llavePublicaServidor = llavePublicaServidor;
		try {
			this.llavePrivadaCliente = Criptografia.generarLlavesRSA().getPrivate();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		conectar();
		
	}

	private void conectar() {
		
		try (Socket socket = new Socket(direccionServidor, puertoServidor)) {
	        System.out.println("Conectado al servidor en " + direccionServidor + ":" + puertoServidor);

	        protocoloConsulta(socket);

	    } catch (IOException e) {
	        System.out.println("Error conectando al servidor: " + e.getMessage());
	        e.printStackTrace();
	    }
		
	}

	public static void protocoloConsulta(Socket socket) {
		//Diffie-Hellman, recibe tabla, elige servicio, envía id, etc.
		//mostrarServicios(Map<Integer, String> servicios)
		//seleccionarServicio(Set<Integer> serviciosIdsDisponibles)
	}

	public static void mostrarServicios(Map<Integer, String> servicios) {
		
	}
	
	private int seleccionarServicio(Set<Integer> serviciosIdsDisponibles) {
		
		List<Integer> listaIds = new ArrayList<>(serviciosIdsDisponibles);
	    Random rng = new Random();
	    int indice = rng.nextInt(listaIds.size());
	    int idSeleccionado = listaIds.get(indice);

	    System.out.println("Servicio aleatorio: " + idSeleccionado);
	    return idSeleccionado;
		
	}
	
	public static boolean verificarFirma(byte[] datos, byte[] firma) {
		return false;
		
	}
	
	public static byte[] descifrarAES(byte[] datos, SecretKey llaveAES, IvParameterSpec iv) {
		return datos;
		
	}
	
	public static boolean verificarHMAC(byte[] datos, byte[] hmacRecibido, SecretKey llaveHMAC) {
		return false;
		
	}
	
}
