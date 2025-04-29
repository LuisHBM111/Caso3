import java.util.concurrent.atomic.AtomicLong;

public class EstadisticasGlobales {
    public static AtomicLong totalTiempoFirma = new AtomicLong(0);
    public static AtomicLong totalTiempoCifrado = new AtomicLong(0);
    public static AtomicLong totalTiempoVerificacionHMAC = new AtomicLong(0);

    public static void reset() {
        totalTiempoFirma.set(0);
        totalTiempoCifrado.set(0);
        totalTiempoVerificacionHMAC.set(0);
    }
}
 