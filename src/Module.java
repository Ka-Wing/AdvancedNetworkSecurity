import org.jnetpcap.packet.PcapPacket;
import org.json.JSONObject;

public interface Module {

    JSONObject inspect(PcapPacket p) throws Exception;

    boolean checkHeader(PcapPacket p);

}
