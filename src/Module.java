import org.jnetpcap.packet.PcapPacket;
import org.json.JSONObject;

/**
 * The module interface to attach to the IDPS.
 */
public interface Module {

    JSONObject inspect(PcapPacket p) throws Exception;

    boolean checkHeader(PcapPacket p);

}
