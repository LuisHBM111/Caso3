public class HiloCliente extends Thread {

    private int id;

    public HiloCliente(int id) {
        this.id = id;
    }

    @Override
    public void run() {
        try {
            System.out.println("[Cliente " + id + "] Iniciando conexión...");
            Cliente.main(null); // Reutilizamos tu Cliente actual
            System.out.println("[Cliente " + id + "] Finalizado.");
        } catch (Exception e) {
            System.out.println("[Cliente " + id + "] Error durante la ejecución.");
            e.printStackTrace();
        }
    }
}
