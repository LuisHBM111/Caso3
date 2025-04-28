
public class Servicio {
	
	int id;
	String nombre;
	String ip;
	int puerto;
	
	public Servicio(int id, String nombre, String ip, int puerto) {
		super();
		this.id = id;
		this.nombre = nombre;
		this.ip = ip;
		this.puerto = puerto;
	}
	
	public int getId() {
		return id;
	}
	public void setId(int id) {
		this.id = id;
	}
	public String getNombre() {
		return nombre;
	}
	public void setNombre(String nombre) {
		this.nombre = nombre;
	}
	public String getIp() {
		return ip;
	}
	public void setIp(String ip) {
		this.ip = ip;
	}
	public int getPuerto() {
		return puerto;
	}
	public void setPuerto(int puerto) {
		this.puerto = puerto;
	}

}
