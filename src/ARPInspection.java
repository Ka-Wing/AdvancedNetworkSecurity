import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.json.JSONObject;
import java.io.*;

public class ARPInspection implements Module {

    Database database;


    public ARPInspection(String configurationFile) throws Exception {
        database = Database.getInstance();
        loadDatabase(configurationFile);
    }

    public void loadDatabase(String file) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(new File(file)));

        String line;
        int lineNumber = 1;

        while((line = br.readLine()) != null) {
            String[] binding = line.split(" ");
            if (binding.length != 2 || !StaticMethods.isValidIP(binding[0]) || !StaticMethods.isValidMAC(binding[1])) {
                throw new Exception("Configuration file format error at line " + lineNumber + ".");
            }

            database.setValue(binding[0], binding[1]);
            lineNumber ++;
        }
    }

    @Override
    public boolean checkHeader(PcapPacket packet) {
        return packet.hasHeader(new Arp());
    }

    public JSONObject parsePacket(PcapPacket packet) throws Exception {
        Ethernet ethernetHeader = packet.getHeader(new Ethernet());
        Arp arpHeader = packet.getHeader(new Arp());

        JSONObject packetJSONObject = new JSONObject();
        JSONObject ethernetJSONObject = new JSONObject();
        JSONObject arpJSONObject = new JSONObject();


        ethernetJSONObject.put("src", StaticMethods.convertMacAddressByteToString(ethernetHeader.source()));
        ethernetJSONObject.put("dst" , StaticMethods.convertMacAddressByteToString(ethernetHeader.destination()));
        arpJSONObject.put("opcode", arpHeader.operationDescription().toLowerCase());
        arpJSONObject.put("hrd", arpHeader.hardwareTypeDescription().toLowerCase());
        arpJSONObject.put("pro", arpHeader.protocolTypeDescription().toLowerCase());
        arpJSONObject.put("hln", arpHeader.hlen());
        arpJSONObject.put("pln", arpHeader.plen());
        arpJSONObject.put("tpa", StaticMethods.convertIpAddressByteToString(arpHeader.tpa()));
        arpJSONObject.put("tha", StaticMethods.convertMacAddressByteToString(arpHeader.tha()));
        arpJSONObject.put("spa", StaticMethods.convertIpAddressByteToString(arpHeader.spa()));
        arpJSONObject.put("sha", StaticMethods.convertMacAddressByteToString(arpHeader.sha()));

        packetJSONObject.put("ethernet", ethernetJSONObject);
        packetJSONObject.put("arp", arpJSONObject);


        return packetJSONObject;
    }

    public boolean broadcastBindingViolation(String sourceHardwareAddress, String targetHardwareAddress, String
            opcode) {
        String broadcastAddress = "ff:ff:ff:ff:ff:ff";
        if (opcode.equals("reply")) {
            return sourceHardwareAddress.equals(broadcastAddress) || targetHardwareAddress.equals(broadcastAddress);
        } else {
            return false;
        }
    }

    public boolean localhostAddressViolation(String senderIPAddress, String opcode) {
        if (opcode.equals("reply")) {
            return senderIPAddress.equals("127.0.0.1");
        } else {
            return false;
        }
    }

    public boolean duplicateIPAddress(String senderIPAddress, String senderHardwareAddress) {
        String macAddress = database.getValue(senderIPAddress);

        if (!(macAddress == null) && !macAddress.equals(senderHardwareAddress)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean arpReplyNotSendToBroadcastAddressViolation(String destination, String opcode) {
        if (opcode.equals("request")) {
            return !destination.equals("ff:ff:ff:ff:ff:ff");
        } else {
            return false;
        }
    }

    /**
     * Check if MAC address of source is the same as the sender's MAC address in the ARP packet, or if the MAC
     * address of the destination is the same as the target's MAC address in the ARP packet, if the ARP packet is an
     * ARP reply.
     *
     * @param source Ethernet source MAC address.
     * @param senderHardwareAddress ARP sender's MAC address
     * @param destination Ethernet destination MAC address
     * @param targetHardwareAddress ARP target's MAC address.
     * @param opcode Opcode of ARP packet.
     * @return true if violation occurs, else false.
     */
    public boolean packetInternalInconsistencyViolation(String source, String senderHardwareAddress, String
            destination, String targetHardwareAddress, String opcode) {
        if (!source.equals(senderHardwareAddress) || (destination.equals(targetHardwareAddress) && opcode.equals
                ("reply"))) {
            return true;
        } else {
            return false;
        }
    }

    @Override
    public JSONObject inspect(PcapPacket packet) throws Exception {
        if (!checkHeader(packet)) {
            return null;
        }

        JSONObject jsonObject = parsePacket(packet);
        String opcode = (String) ((JSONObject) jsonObject.get("arp")).get("opcode");
        String src = (String) ((JSONObject) jsonObject.get("ethernet")).get("src");
        String dst = (String) ((JSONObject) jsonObject.get("ethernet")).get("dst");
        String tha = (String) ((JSONObject) jsonObject.get("arp")).get("tha");
        String sha = (String) ((JSONObject) jsonObject.get("arp")).get("sha");
        String spa = (String) ((JSONObject) jsonObject.get("arp")).get("spa");


        if (broadcastBindingViolation(sha, tha, opcode)) {
            jsonObject.put("arp", ((JSONObject) jsonObject.get("arp")).put("action", "error"));
            jsonObject.put("arp",
                    ((JSONObject) jsonObject.get("arp")).put("actionreason", "Tries to bind to broadcast address."));
        } else if (localhostAddressViolation(spa, opcode)) {
            jsonObject.put("arp", ((JSONObject) jsonObject.get("arp")).put("action", "error"));
            jsonObject.put("arp",
                    ((JSONObject) jsonObject.get("arp")).put("actionreason", "Tries to bind to localhost address " +
                            "(127.0.0.1)."));
        } else if (duplicateIPAddress(spa, sha)) {
            jsonObject.put("arp", ((JSONObject) jsonObject.get("arp")).put("action", "notice"));
            jsonObject.put("arp",
                    ((JSONObject) jsonObject.get("arp")).put("actionreason", "Duplicate IP address detected for " +
                            spa + "."));
        } else if (arpReplyNotSendToBroadcastAddressViolation(dst, opcode)) {
            jsonObject.put("arp", ((JSONObject) jsonObject.get("arp")).put("action", "notice"));
            jsonObject.put("arp",
                    ((JSONObject) jsonObject.get("arp")).put("actionreason", "ARP request not sent to the broadcast " +
                            "address"));
        } else if (packetInternalInconsistencyViolation(src, sha, dst, tha, opcode)) {
            jsonObject.put("arp", ((JSONObject) jsonObject.get("arp")).put("action", "notice"));
            jsonObject.put("arp",
                    ((JSONObject) jsonObject.get("arp")).put("actionreason", "ARP packets not internally consistent " +
                            "w.r.t MAC addresses."));
        }

        return jsonObject;

    }

}
