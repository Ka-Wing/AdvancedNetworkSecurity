import org.jnetpcap.packet.PcapPacket;
import org.json.JSONObject;

/**
 * The module interface to attach to the IDPS.
 */
public interface Module {

    // Inspects the pcap file.
    JSONObject inspect(PcapPacket p) throws Exception;

    // Checks if certain headers exists.
    boolean checkHeader(PcapPacket p);

}
