import org.jnetpcap.*;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.PcapPacket;

public class Project1 {

    private String file;
    private StringBuilder errorBuffer;

    public Project1(String file) {
        this.file = file;
    }

    public void readPcap() {
        this.errorBuffer = new StringBuilder();
        Pcap p = Pcap.openOffline(this.file, this.errorBuffer);
    }

    public static void main(String[] args) {
        System.out.println("Pcap at " + args[0]);
        Project1 p = new Project1(args[0]);
        p.readPcap();
    }

}
