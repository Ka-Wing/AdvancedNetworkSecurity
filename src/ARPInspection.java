import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Arp;
import org.json.JSONObject;

import java.util.Set;

/**
 * ARP inspector to inspect ARP and check for potential attacks.
 */
public class ARPInspection implements Module {

    private DAIDatabase daiDatabase;


    public ARPInspection() {
        daiDatabase = DAIDatabase.getInstance();
    }

    /**
     * Checks if packet has an ARP header.
     * @param packet The packet
     * @return true if packet als ARP header.
     */
    @Override
    public boolean checkHeader(PcapPacket packet) {
        return packet.hasHeader(new Arp());
    }

    /**
     * Parsing the packet.
     * @param packet The packet.
     * @return a JSONObject with Ethernet source/destination address, ARP opcode, hardware type, protocol type,
     * hardware size, protocol size, sender MAC and IP address and target's MAC and IP address.
     * @throws Exception If something fails horribly.
     */
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

    /**
     * Checks if source tries to bind with the broadcast address "ff:ff:ff:ff:ff:ff"
     * @param sourceHardwareAddress MAC address of the source in the ARP header.
     * @param targetHardwareAddress MAC address of the target in the ARP header.
     * @param opcode Opcode of the ARP header.
     * @return true if rule is violated, else false.
     */
    public boolean broadcastBindingViolation(String sourceHardwareAddress, String targetHardwareAddress, String
            opcode) {
        String broadcastAddress = "ff:ff:ff:ff:ff:ff";

        return opcode.equals("reply") && (sourceHardwareAddress.equals(broadcastAddress) || targetHardwareAddress
                .equals(broadcastAddress));
    }

    /**
     * Checks if source tries to bind with special localhost IP address "127.0.0.1"
     * @param senderIPAddress IP address of the source in the ARP header.
     * @param opcode Opcode of the ARP header.
     * @return true if rule is violated, else false.
     */
    public boolean localhostAddressViolation(String senderIPAddress, String opcode) {
        return opcode.equals("reply") && senderIPAddress.equals("127.0.0.1");
    }

    /**
     * Checks if one MAC address uses another IP address than is allocated to.
     * @param senderIPAddress sender's IP address
     * @param senderHardwareAddress sender's IP address in the ARP header.
     * @return string of duplicate IP address, else return null.
     */
    public String duplicateIPAddress(String senderIPAddress, String senderHardwareAddress) {
        Set<String> ipAddresses = daiDatabase.getKeys();

        for (String ipAddress : ipAddresses) {
            if (!ipAddress.equals(senderIPAddress) && daiDatabase.getValue(ipAddress).equals(senderHardwareAddress) ) {
                return ipAddress;
            }
        }

        return null;
    }

    /**
     * Checks if an ARP request is sent to the broadcast address "ff:ff:ff:ff:ff:ff"
     * @param destination MAC address of the destination.
     * @param opcode Opcode of the ARP header.
     * @return true if the ARP request is NOT sent to the broadcast address, else false.
     */
    public boolean arpRequestNotSentToBroadcastAddressViolation(String destination, String opcode) {
        return opcode.equals("request")&& !destination.equals("ff:ff:ff:ff:ff:ff");
    }

    /**
     * Checks if an ARP reply is sent to the broadcast address "ff:ff:ff:ff:ff:ff"
     * @param destination MAC address of the destination.
     * @param opcode Opcode of the ARP header.
     * @return true if the ARP reply is sent to the broadcast address, else false.
     */
    public boolean arpReplySentToBroadcastAddressViolation(String destination, String opcode) {
        return opcode.equals("reply") && destination.equals("ff:ff:ff:ff:ff:ff");
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

        return !source.equals(senderHardwareAddress) || (!destination.equals(targetHardwareAddress) && opcode.equals
                ("reply"));
    }

    /**
     * Checks if the destination MAC address of an ARP request has only zeroes.
     * @param targetHardwareAddress the destination MAC address.
     * @param opcode Opcode of ARP packet.
     * @ true if rule is violated, else false.
     */
    public boolean arpRequestDestinationIPAddressNotZeroesViolation(String targetHardwareAddress, String opcode) {
        return opcode.equals("request") && !(targetHardwareAddress.equals("0:0:0:0:0:0") || targetHardwareAddress.equals
                ("00:00:00:00:00:00"));
    }

    /**
     * Inspects the packet and see if any rules are violated.
     * @param packet The packet.
     * @return JSONObject with packet information.
     * @throws Exception If something fails horribly.
     */
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

        JSONObject idsJSONObject = new JSONObject();

        if (broadcastBindingViolation(sha, tha, opcode)) {
            idsJSONObject.put("action", "error");
            idsJSONObject.put("reason", "Tries to bind to broadcast address.");

            Logger.getInstance().logError(tha + " tries to bind to ff:ff:ff:ff:ff:ff");
        } else if (localhostAddressViolation(spa, opcode)) {
            idsJSONObject.put("action", "error");
            idsJSONObject.put("reason", "Tries to bind to localhost address (127.0.0.1).");
            Logger.getInstance().logError(tha + " tries to bind to 127.0.0.1");
        } else if (duplicateIPAddress(spa, sha) != null) {
            idsJSONObject.put("action", "notice");
            idsJSONObject.put("reason", "Duplicate IP address detected for " + spa + ".");

            Logger.getInstance().logNotice(tha + " is bound with " + duplicateIPAddress(spa, sha) + ", but another " +
                    "IP address " + spa + " is used for an ARP packet.");
        } else if (arpRequestNotSentToBroadcastAddressViolation(dst, opcode)) {
            idsJSONObject.put("action", "notice");
            idsJSONObject.put("reason", "ARP request not sent to the broadcast address");

            Logger.getInstance().logNotice(src + " sends an ARP request, but not to the broadcast address.");
        } else if (arpReplySentToBroadcastAddressViolation(dst, opcode)) {
            idsJSONObject.put("action", "notice");
            idsJSONObject.put("reason", "ARP reply was sent to the broadcast address");
            Logger.getInstance().logNotice(src + " sends an ARP reply to the broadcast address.");
        } else if (packetInternalInconsistencyViolation(src, sha, dst, tha, opcode)) {
            idsJSONObject.put("action", "notice");
            idsJSONObject.put("reason", "ARP packets not internally consistent w.r.t MAC addresses.");

            String noticeMessage = "ARP packet internally inconsistent w.r.t. MAC address: ";
            if (!src.equals(sha)) {
                noticeMessage += "sender MAC addresses " + src + " and " + sha + ". ";
            }

            if (!dst.equals(tha)) {
                noticeMessage += "target MAC addresses " + dst + " and " + tha + ".";
            }
            Logger.getInstance().logNotice(noticeMessage);
        } else if (arpRequestDestinationIPAddressNotZeroesViolation(tha, opcode)) {
            idsJSONObject.put("action", "notice");
            idsJSONObject.put("reason", "Target Hardward Address of an ARP request is not only zeroes.");
            Logger.getInstance().logNotice("ARP request's MAC address should be 0:0:0:0:0:0, but is " + tha + " " +
                    "instead." );
        } else {
            idsJSONObject.put("action", "permitted");
        }

        jsonObject.put("ids", idsJSONObject);

        return jsonObject;

    }

}
