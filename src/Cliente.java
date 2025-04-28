import java.io.IOException;
import java.net.Socket;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Cliente {
	
	String direccionServidor;
	static int puertoServidor;
	PublicKey llavePublicaServidor;

	public static void main(String[] args) {
		//conectar();

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
