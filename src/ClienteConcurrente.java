public class ClienteConcurrente {

    public static void main(String[] args) {
        int cantidadClientes = 16; // Cambia esto a 4, 16, 32, 64 según pruebas

        Thread[] clientes = new Thread[cantidadClientes];

        long inicio = System.currentTimeMillis();

        for (int i = 0; i < cantidadClientes; i++) {
            clientes[i] = new HiloCliente(i + 1);
            clientes[i].start();
            try {
				Thread.sleep(1000);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
        }

        // Esperar a que todos terminen
        for (int i = 0; i < cantidadClientes; i++) {
            try {
                clientes[i].join();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        long fin = System.currentTimeMillis();
        System.out.println("🧪 Todos los " + cantidadClientes + " clientes han terminado.");
        System.out.println("\n📊 Estadísticas totales de todos los clientes:");
        System.out.println("⏱ Tiempo total de firma: " + EstadisticasGlobales.totalTiempoFirma.get() + " ns");
        System.out.println("⏱ Tiempo total de cifrado: " + EstadisticasGlobales.totalTiempoCifrado.get() + " ns");
        System.out.println("⏱ Tiempo total de verificación HMAC: " + EstadisticasGlobales.totalTiempoVerificacionHMAC.get() + " ns");
    }
}
