import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.json.JSONObject;

import java.io.*;
import java.util.HashMap;

public class ARPInspection implements Module {

    private HashMap<String, String> binding;


    public ARPInspection(String configurationFile) throws Exception {
        this.binding = getBindings(configurationFile);
    }


    public HashMap<String, String> getBindings(String file) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(new File(file)));
        HashMap<String, String> hashmap = new HashMap<>();

        String line;
        int lineNumber = 1;

        while((line = br.readLine()) != null) {
            String[] binding = line.split(" ");
            if (binding.length != 2 || !StaticMethods.isValidIP(binding[0]) || !StaticMethods.isValidMAC(binding[1])) {
                throw new Exception("Configuration file format error at line " + lineNumber + ".");
            }

            hashmap.put(binding[0], binding[1]);
            lineNumber ++;
        }

        return hashmap;
    }

    @Override
    public boolean checkHeader(PcapPacket p) {
        return p.hasHeader(new Arp());
    }

    @Override
    public JSONObject inspect(PcapPacket p) throws Exception {
        if (!checkHeader(p)) {
            return null;
        }

        Ethernet ethernetHeader = p.getHeader(new Ethernet());
        Arp arpHeader = p.getHeader(new Arp());

        JSONObject packetJSONObject = new JSONObject();
        JSONObject ethernetJSONObject = new JSONObject();
        JSONObject arpJSONObject = new JSONObject();


        ethernetJSONObject.put("src", StaticMethods.convertMacAddressByteToString(ethernetHeader.source()));
        ethernetJSONObject.put("dest" , StaticMethods.convertMacAddressByteToString(ethernetHeader.destination()));
        arpJSONObject.put("opcode", arpHeader.operationDescription());
        arpJSONObject.put("hrd", arpHeader.hardwareTypeDescription());
        arpJSONObject.put("pro", arpHeader.protocolTypeDescription());
        arpJSONObject.put("hln", arpHeader.hlen());
        arpJSONObject.put("pln", arpHeader.plen());
        arpJSONObject.put("tpa", StaticMethods.convertIpAddressByteToString(arpHeader.tpa()));
        arpJSONObject.put("tha", StaticMethods.convertMacAddressByteToString(arpHeader.tha()));
        arpJSONObject.put("spa", StaticMethods.convertIpAddressByteToString(arpHeader.spa()));
        arpJSONObject.put("sha", StaticMethods.convertMacAddressByteToString(arpHeader.sha()));
        arpJSONObject.put("action", "error");

        packetJSONObject.put("ethernet", ethernetJSONObject);
        packetJSONObject.put("arp", arpJSONObject);


        return packetJSONObject;
    }

}
