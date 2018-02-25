import org.jnetpcap.*;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.util.PcapPacketArrayList;
import org.json.*;

import java.io.*;

public class DNSParser implements Module {

    private String pcapFilePath;
    private Pcap pcap;
    private StringBuilder errorBuffer;
    byte[] transportLayerPayload; // TCP/UDP payload of the packet, used when DNS name has pointers with offsets.

    public DNSParser(String file) {
        this.pcapFilePath = file;
        errorBuffer = new StringBuilder();
    }

    public DNSParser() {
        errorBuffer = new StringBuilder();
    }

    /**
     * This method reads all packets in a pcap file and outputs a json file with information of the DNS packet. Packets
     * will be filtered on TCP/UDP packets on port 53.
     * @throws Exception When something goes horribly wrong.
     */
    public void readPcapFile() throws Exception {
        this.errorBuffer = new StringBuilder();
        // Loads the Pcap file.
        this.pcap = Pcap.openOffline(this.pcapFilePath, this.errorBuffer);
        PcapBpfProgram bpf = new PcapBpfProgram();

        // Filter on tcp/ip, udp/ip, tcp/ip6 and udp/ip6 on port 53 with netmask "255.255.255.0".
        pcap.compile(bpf, "port 53", 0, 0xFFFFFF00);
        pcap.setFilter(bpf);

        // If opening the file fails.
        if (this.pcap == null) {
            throw new Exception(errorBuffer.toString());
        }

        PcapPacketHandler<PcapPacketArrayList> jPacketHandler =
                (pcapPacket, pcapPackets) -> pcapPackets.add(pcapPacket);

        try {
            // Retrieve all packets in the pcap file and puts the packets in a PcapPacketArrayList.
            PcapPacketArrayList packets = new PcapPacketArrayList();
            this.pcap.loop(-1, jPacketHandler, packets);
            int index = 1; // Index of the packet being read when looping through all packets.

            // JSON output.
            JSONObject packetsJSONObject = new JSONObject();

            // Statistics variables
            int parsingSuccessful = 0;
            int parsingFailed = 0;

            for (PcapPacket packet : packets) {
                try {
                    packetsJSONObject.put("packet_" + index, inspect(packet));
                    System.out.println("Packet " + index + " completed.");
                    parsingSuccessful ++;

                } catch (Exception e) {
                    System.out.println("Packet_" + index + " could not be parsed (completely).");
                    parsingFailed ++;
                } finally {
                    index = index + 1;
                }

            }

            System.out.println();
            System.out.println(parsingSuccessful + " packets parsed successfully");
            System.out.println(parsingFailed + " packets failed");
            String fileName = "json.json";
            StaticMethods.saveJSONToFile(packetsJSONObject, fileName);
            System.out.println("File saved to " + fileName);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            this.pcap.close();
        }

    }

    /**
     * Parses the packet.
     * @param packet The packet that has to be parsed.
     * @return A JSONObject object containing information of the packet
     * @throws Exception When something goes horribly wrong.
     */
    @Override
    public JSONObject inspect(PcapPacket packet) throws Exception {
        // If not DNS.
        if (!checkHeader(packet)) {
            return null;
        }

        JSONObject packetJSONObject = new JSONObject();

        Ethernet ethernetHeader = packet.getHeader(new Ethernet());

        //Header object used to store ip4 or ip6 header.
        JHeader ipHeader;

        // Header object used to store TCP or UDP header.
        JHeader transportLayerHeader;

        ByteArrayInputStream ethernetHeaderPayloadByteArrayInputStream =
                new ByteArrayInputStream(ethernetHeader.getPayload());

        int internetProtocolVersion = getInternetProtocolVersion(getDataInputStream(ethernetHeader.getPayload()));
        String transportLayerProtocol =
                getTransportLayerProtocol(new DataInputStream(ethernetHeaderPayloadByteArrayInputStream), internetProtocolVersion);
        JSONObject addressesJSONObject;

        if (internetProtocolVersion == 4) {
            addressesJSONObject = decodeInternetProtocol4(getDataInputStream(ethernetHeader.getPayload()));
            ipHeader = packet.getHeader(new Ip4());
        } else { // Because of the filter, if it is not ip4, then it is IP6
            addressesJSONObject = decodeInternetProtocol6(getDataInputStream(ethernetHeader.getPayload()));
            ipHeader = packet.getHeader(new Ip6());
        }

        JSONObject portsJSONObject = getPorts(getDataInputStream(ipHeader.getPayload()));

        JSONObject ipJSONObject = StaticMethods.appendJSONObject(addressesJSONObject, portsJSONObject);


        if (transportLayerProtocol.equals("TCP")) {
            transportLayerHeader = packet.getHeader(new Tcp());
        } else { // Because of the filter, if it is not tcp, then it is udp
            transportLayerHeader = packet.getHeader(new Udp());
        }

        this.transportLayerPayload = transportLayerHeader.getPayload();
        DataInputStream dataInputStream = getDataInputStream(transportLayerPayload);

        JSONObject headerJSONObject;
        // DNS data Decoding
        if (transportLayerProtocol.equals("TCP")) {
            headerJSONObject = this.decodingHeaderSection(dataInputStream, true);
        } else { // else UDP
            headerJSONObject = this.decodingHeaderSection(dataInputStream, false);
        }
        JSONArray questionJSONArray = this.decodingQuestionSection(dataInputStream, (int) headerJSONObject.get("qdcount"));
        JSONArray answerJSONArray = this.decodingRecordSection(dataInputStream, (int) headerJSONObject.get("ancount"));
        JSONArray authorityJSONArray = this.decodingRecordSection(dataInputStream, (int) headerJSONObject.get("nscount"));
        JSONArray additionalJSONArray = this.decodingRecordSection(dataInputStream, (int) headerJSONObject.get("arcount"));

        packetJSONObject.put("ipv" + internetProtocolVersion, ipJSONObject);
        packetJSONObject.put("header", headerJSONObject);
        packetJSONObject.put("question", questionJSONArray);
        packetJSONObject.put("answer", answerJSONArray);
        packetJSONObject.put("authority", authorityJSONArray);
        packetJSONObject.put("additional", additionalJSONArray);

        return packetJSONObject;
    }

    /**
     * For both UDP and TCP, retrieve the source port and destination port.
     * @param dataInputStream Object with the payload loaded.
     * @return JSONObject object with source port and destination port
     * @throws IOException If reading the payload goes wrong.
     * @throws JSONException If JSON goes wrong.
     */
    private JSONObject getPorts(DataInputStream dataInputStream) throws IOException, JSONException {
        JSONObject ports = new JSONObject();

        // Appends the next two bytes.
        String sourcePortBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int sourcePort = Integer.parseInt(sourcePortBinary, 2);

        // Appends the next two bytes.
        String destinationPortBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int destinationPort = Integer.parseInt(destinationPortBinary, 2);

        ports.put("srcport", sourcePort);
        ports.put("dstport", destinationPort);

        return ports;

    }

    /**
     * Returns a DataInputStream with a given byte array.
     *
     * @param payload byte array.
     * @return DataInputStream object with the given byte array loaded.
     */
    private DataInputStream getDataInputStream(byte[] payload) {
        return new DataInputStream(new ByteArrayInputStream(payload));
    }

    /**
     * Retrieves the IP version of a Ethernet header payload.
     *
     * @param dataInputStream DataInputStream object with Ethernet header loaded.
     * @return The IP version.
     * @throws IOException If reading the payload goes wrong.
     */
    private int getInternetProtocolVersion(DataInputStream dataInputStream) throws IOException {
        String versionBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))).substring(0, 4);
        return Integer.parseInt(versionBinary, 2);
    }
    

    /**
     * Retrieves the transport layer protocol from a given DataInputStream object with the IP4/IP6 header loaded
     *
     * @param dataInputStream DataInputStream object with the IP4/IP6 header loaded
     * @param internetProtocolVersion The IP version.
     * @return The transport layer protocol
     * @throws IOException If reading the payload goes wrong.
     */
    private String getTransportLayerProtocol(DataInputStream dataInputStream, int internetProtocolVersion) throws IOException {
        // Skip to protocol section
        if (internetProtocolVersion == 4) {
            dataInputStream.skipBytes(9);
        } else if (internetProtocolVersion == 6) {
            dataInputStream.skipBytes(6);
        }

        int protocol = StaticMethods.unsignByte(dataInputStream.readByte());

        if (protocol == 6) {
            return "TCP";
        } else if (protocol == 17) {
            return "UDP";
        }

        return "NOTTCPUDP";

    }


    /**
     * Returns a JSONObject object with the source IP4 address and destination IP4 address.
     *
     * @param dataInputStream DataInputStream object with Ethernet header payload loaded.
     * @return a JSONObject object with the source IP4 address and destination IP4 address.
     * @throws IOException If reading the payload goes wrong.
     * @throws JSONException If JSON goes wrong.
     */
    private JSONObject decodeInternetProtocol4(DataInputStream dataInputStream) throws IOException, JSONException {
        // Jump to source address.
        dataInputStream.skipBytes(12);

        String sourceAddress = "";
        // First four bytes from offset 12 denotes the source IP address.
        for (int i = 0; i < 4; i++) {
            // Get the unsigned byte and append them.
            sourceAddress += StaticMethods.unsignByte(dataInputStream.readByte()) + ".";
        }

        // Remove the dot at the end.
        sourceAddress = sourceAddress.substring(0, sourceAddress.length() - 1);

        String destinationAddress = "";
        // Next four bytes denotes the destination IP address.
        for (int i = 0; i < 4; i++) {
            // Get the unsigned byte and append them.
            destinationAddress += StaticMethods.unsignByte(dataInputStream.readByte()) + ".";
        }
        destinationAddress = destinationAddress.substring(0, destinationAddress.length() - 1);

        JSONObject addressesJSONObject = new JSONObject();
        addressesJSONObject.put("srcip", sourceAddress);
        addressesJSONObject.put("dstip", destinationAddress);

        return addressesJSONObject;

    }

    /**
     * Returns a JSONObject object with the source IPv6 address and destination IPv6 address. NOTE: Does not use double
     * colon for consecutive zero sections. Instead it returns a full IPv6 address.
     *
     * @param dataInputStream DataInputStream object with Ethernet header payload loaded.
     * @return a JSONObject object with the source IP6 address and destination IPv6 address.
     * @throws IOException If reading the payload goes wrong.
     * @throws JSONException If JSON goes wrong.
     */
    private JSONObject decodeInternetProtocol6(DataInputStream dataInputStream) throws IOException, JSONException {
        // Skip to source address
        dataInputStream.skipBytes(8);

        String sourceAddress = "";
        String destinationAddress = "";

        // Append the next 16 bytes
        for (int i = 0; i < 16; i ++) {
            sourceAddress += Integer.toHexString(StaticMethods.unsignByte(dataInputStream.readByte()));
            if(i % 2 != 0) {
                sourceAddress += ":";
            }
        }

        // Appends the next 16 bytes
        for (int i = 0; i < 16; i ++) {
            destinationAddress += Integer.toHexString(StaticMethods.unsignByte(dataInputStream.readByte()));
            if(i % 2 != 0) {
                destinationAddress += ":";
            }
        }

        // Removes the final colon
        sourceAddress = sourceAddress.substring(0, sourceAddress.length() - 1);
        destinationAddress = destinationAddress.substring(0, destinationAddress.length() - 1);

        JSONObject addressesJSONObject = new JSONObject();
        addressesJSONObject.put("srcip", sourceAddress);
        addressesJSONObject.put("dstip", destinationAddress);

        return addressesJSONObject;


    }

    /**
     * Decodes the domain name in the question, answer, authority and additional section.
     *
     * @param dataInputStream The DataInputStream object that has already read the bytes up til the domain name bytes.
     * @return The decoded domain name.
     * @throws Exception
     */
    private String decodingName(DataInputStream dataInputStream) throws Exception {
        StringBuilder name = new StringBuilder();

        // Stores how many time a byte is read, to skip the last byte if needed.
        //int bytesRead = 0;

        while(true) {
            // Read the next byte as length, convert from signed byte to unsigned byte.
            int length = StaticMethods.unsignByte(dataInputStream.readByte());
            String lengthBinary = StaticMethods.appendZero(Integer.toBinaryString(length));
            //bytesRead ++;

            // Check if name is a pointer
            if(lengthBinary.charAt(0) == '1' && lengthBinary.charAt(1) == '1') {

                // Pointer of name in binary
                String pointerBinary = lengthBinary +
                        StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));

                // Remove the first two binary numbers (both set to '1'), and use the remaining 14 bits as offset.
                int offset = Integer.parseInt(pointerBinary.substring(2, pointerBinary.length()), 2);

                // New DataInputStream object starting from given offset.
                DataInputStream dis = getDataInputStream(this.transportLayerPayload);
                dis.skipBytes(offset);

                // Add name to the stringbuilder.
                name.append(this.decodingName(dis) + "."); // Add '.', so it can be removed after this while-loop.
                break;
            }

            if(length == 0) {
                break;
            }

            // Turn the bytes into ASCII and append them.
            for(int j = 0; j < length; j ++) {
                int decimalValue = StaticMethods.unsignByte(dataInputStream.readByte());
                char asciiCharacter = (char) decimalValue;
                name.append(asciiCharacter);
            }

            name.append(".");
        }

        //Removes last dot
        if (name.length() > 0) {
            name = name.deleteCharAt(name.length() - 1);
        }

        return name.toString();
    }

    /**
     * Decodes the question type.
     * @param binary A binary representing the question type.
     * @return The question type.
     * @throws Exception When something goes wrong.
     */
    private String decodingQType(String binary) throws Exception {

        int QType = Integer.parseInt(binary, 2);
        //{AXFR, MAILB, MAILA, *}

        if (QType == 1) {
            return "A";
        } else if (QType == 2) {
            return "NS";
        } else if (QType == 3) {
            return "MD";
        } else if (QType == 4) {
            return "MF";
        } else if (QType == 5) {
            return "CNAME";
        } else if (QType == 6) {
            return "SOA";
        } else if (QType == 7) {
            return "MB";
        } else if (QType == 8) {
            return "MG";
        } else if (QType == 9) {
            return "MR";
        } else if (QType == 10) {
            return "NULL";
        } else if (QType == 11) {
            return "WKS";
        } else if (QType == 12) {
            return "PTR";
        } else if (QType == 13) {
            return "HINFO";
        } else if (QType == 14) {
            return "MINFO";
        } else if (QType == 15) {
            return "MX";
        } else if (QType == 16) {
            return "TXT";
        } else if (QType == 252) {
            return "AXFR";
        } else if (QType == 253) {
            return "MAILB";
        } else if (QType == 4) {
            return "MAILA";
        } else if (QType == 255) {
            return "*";
        } else {
            throw new Exception("QClass \"" + QType + "\" unknown.");
        }
    }

    /**
     * Decodes the question class.
     *
     * @param binary A binary representing the question class.
     * @return The question class.
     * @throws Exception When something goes wrong.
     */
    private String decodingQClass(String binary) throws Exception {
        int QClass = Integer.parseInt(binary, 2);

        if (QClass == 1) {
            return "IN";
        } else if(QClass == 2) {
            return "CS";
        } else if (QClass == 3) {
            return "CH";
        } else if (QClass == 4) {
            return "HS";
        } else if (QClass == 254) {
            return "NONE";
        } else if (QClass == 255) {
            return "*";
        } else {
            throw new Exception("QClass \"" + QClass + "\" unknown.");
        }
    }

    /**
     * Decodes the RR type
     *
     * @param binary A binary representing the RR type.
     * @return The RR type.
     * @throws Exception When something goes wrong.
     */
    private String decodingRRType(String binary) throws Exception {
        int classType = Integer.parseInt(binary, 2);

        if (classType == 1) {
            return "A";
        } else if (classType == 2) {
            return "NS";
        } else if (classType == 3) {
            return "MD";
        } else if (classType == 4) {
            return "MF";
        } else if (classType == 5) {
            return "CNAME";
        } else if (classType == 6) {
            return "SOA";
        } else if (classType == 7) {
            return "MB";
        } else if (classType == 8) {
            return "MG";
        } else if (classType == 9) {
            return "MR";
        } else if (classType == 10) {
            return "NULL";
        } else if (classType == 11) {
            return "WKS";
        } else if (classType == 12) {
            return "PTR";
        } else if (classType == 13) {
            return "HINFO";
        } else if (classType == 14) {
            return "MINFO";
        } else if (classType == 15) {
            return "MX";
        } else if (classType == 16) {
            return "TXT";
        } else {
            throw new Exception("classType \"" + classType + "\" unknown.");
        }
    }

    /**
     * Decodes the RDATA
     * @param dataInputStream The DataInputStream object that has already read the header and question section and the
     * answer section up until RDATA.
     * @param type Type of answer.
     * @param rdLength RDATA length
     * @return JSONObject with RDATA.
     * @throws Exception When something goes wrong.
     */
    private JSONObject decodingRData(DataInputStream dataInputStream, String type, int rdLength) throws Exception {
        JSONObject rDataJSONObject = new JSONObject();

        if(rdLength == 0) {
            return rDataJSONObject.put("rdata", "");
        }

        if(type.equals("A")) {
            String address = "";
            for (int q = 0; q < rdLength; q ++) {
                address += Integer.parseInt(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())), 2);
                address += ".";
            }

            address = address.substring(0, address.length() - 1);
            rDataJSONObject.put("rdata", address);

        } else if (type.equals("NS") || type.equals("CNAME") || type.equals("PTR") ||
                type.equals("MB") || type.equals("MD") || type.equals("MF") || type.equals("MG") ||
                type.equals("MR")) {
            rDataJSONObject.put("rdata", decodingName(dataInputStream));

        } else if (type.equals("HINFO")) {
            rDataJSONObject.put("CPU", "CPU");
            rDataJSONObject.put("OS", "OS");

        } else if (type.equals("MINFO")) {
            rDataJSONObject.put("rmailbx", decodingName(dataInputStream));
            rDataJSONObject.put("emailbx", decodingName(dataInputStream));

        } else if (type.equals("SOA")) {
            //MName
            String mName = decodingName(dataInputStream);

            //RName
            String rName = decodingName(dataInputStream);

            //Serial
            String serialBinary = "";
            for (int i = 0; i < 4; i++) {
                serialBinary += StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            }
            String serial = String.valueOf(Integer.parseInt(serialBinary, 2));

            //Refresh
            String refreshBinary = "";
            for (int i = 0; i < 4; i++) {
                refreshBinary += StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            }
            int refresh = Integer.parseInt(refreshBinary, 2);

            //Retry
            String retryBinary = "";
            for (int i = 0; i < 4; i++) {
                retryBinary += StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            }
            int retry = Integer.parseInt(retryBinary, 2);

            //Expire
            String expireBinary = "";
            for (int i = 0; i < 4; i++) {
                expireBinary += StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            }
            int expire = Integer.parseInt(expireBinary, 2);

            //Minimum
            String minimumBinary = "";
            for (int i = 0; i < 4; i++) {
                minimumBinary += StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            }
            int minimum = Integer.parseInt(minimumBinary, 2);

            rDataJSONObject.put("MName", mName);
            rDataJSONObject.put("RName", rName);
            rDataJSONObject.put("Serial", serial);
            rDataJSONObject.put("Refresh", refresh);
            rDataJSONObject.put("Retry", retry);
            rDataJSONObject.put("Expire", expire);
            rDataJSONObject.put("Minimum", minimum);

        } else if (type.equals("MX")) {
            String preference = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            String exchange = decodingName((dataInputStream));

            rDataJSONObject.put("Preference", preference);
            rDataJSONObject.put("Exchange", exchange);

        } else if (type.equals("TXT")) {
            String text = "";
            for (int i = 0; i < rdLength; i ++) {
                int decimalValue = StaticMethods.unsignByte(dataInputStream.readByte());
                char asciiCharacter = (char) decimalValue;
                text += asciiCharacter;
            }
            rDataJSONObject.put("rdata", text);

        } else if (type.equals("WKS")) {
            String address = "";
            for (int q = 0; q < 4; q ++) {
                address += Integer.parseInt(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())), 2);
                address += ".";
            }

            //Removes last dot.
            address = address.substring(0, address.length() - 1);

            int protocolNumber = Integer.parseInt(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())), 2);

            JSONObject bitmap = new JSONObject();
            for (int i = 0; i < rdLength - 5; i ++) {
                try {
                    String binary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
                    for (int j = 0; j < binary.length(); j ++) {
                        bitmap.put(String.valueOf(j), binary.substring(j, j + 1));
                    }

                } catch (Exception IOException) {
                    break;
                }
            }


            JSONObject wksJSONObject = new JSONObject();
            wksJSONObject.put("address", address);
            wksJSONObject.put("version", protocolNumber);
            wksJSONObject.put("bitmap", bitmap);
            rDataJSONObject.put("rdata", wksJSONObject);


        } else {
            rDataJSONObject.put("rdata", "");
        }

        return rDataJSONObject;
    }

    /**
     * Returns the class type of a given binary of a resource record.
     * @param binary The binary to be decoded.
     * @return The class type as a String object.
     */
    private String decodingRRClass(String binary) {
        int classType = Integer.parseInt(binary, 2);

        if (classType == 1) {
            return "IN";
        } else if(classType == 2) {
            return "CS";
        } else if (classType == 3) {
            return "CH";
        } else if (classType == 4) {
            return "HS";
        } else if (classType == 254) {
            return "NONE";
        } else if (classType == 255) {
            return "ANY";
        } else {
            return "UNKNOWN";
        }
    }

    /**
     * Decodes the answer, authority and additional section.
     * @param dataInputStream The DataInputStream object that has already read the header and question section.
     * @param ANCount The number of answers
     * @return A JSONArray object containing the decoded answer(s).
     * @throws Exception
     */
    private JSONArray decodingRecordSection (DataInputStream dataInputStream, int ANCount) throws Exception {
        JSONArray answerJSONArray = new JSONArray();

        for (int i = 0; i < ANCount; i ++) {
            JSONObject answerJSONObject = new JSONObject();

            // Decoding NAME
            String name = this.decodingName(dataInputStream);

            // Decoding TYPE
            String typeBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            String type = decodingRRType(typeBinary);

            // Decoding CLASS
            String classTypeBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            String classType = decodingRRClass(classTypeBinary);

            // Decoding TTL
            String timeToLiveBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            int timeToLive = Integer.parseInt(timeToLiveBinary, 2);

            // Decoding RDLENGTH
            String rdLengthBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte()))) +
                    StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            int rdLength = Integer.parseInt(rdLengthBinary, 2);

            // Decoding RDATA
            JSONObject rData = decodingRData(dataInputStream, type, rdLength);

            answerJSONObject.put("name", name);
            answerJSONObject.put("type", type);
            answerJSONObject.put("class", classType);
            answerJSONObject.put("ttl", timeToLive);

            // See if rData has only one record
            try {
                // If so, put only that record
                answerJSONObject.put("rdata", rData.get("rdata"));
            } catch (JSONException e) {
                // If not, put the whole JSONObject.
                answerJSONObject.put("rdata", rData);
            }

            answerJSONArray.put(answerJSONObject);

        }

        return answerJSONArray;
    }

    /**
     * Decodes the question section.
     *
     * @param dataInputStream The DataInputStream object that has already read the header.
     * @param QDCount The number of questions.
     * @return A JSONArray object containing the decoded question(s).
     * @throws Exception
     */
    private JSONArray decodingQuestionSection (DataInputStream dataInputStream, int QDCount) throws Exception {
        JSONArray questionJSONArray = new JSONArray();

        for (int i = 0; i < QDCount; i ++) {
            JSONObject jsonObject = new JSONObject();

            //Decoding QNAME.
            String QName = this.decodingName(dataInputStream);

            // Read next two signed bytes, convert them to unsigned bytes and then both to 8-length binary, then append them.
            String QTypeBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                    + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));

            String QTypeString = decodingQType(QTypeBinary);

            // Read next two signed bytes, convert them to unsigned bytes and then both to 8-length binary, then append them.
            String QClassBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                    + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));

            String QClassString = decodingQClass(QClassBinary);

            jsonObject.put("qname", QName);
            jsonObject.put("qtype", QTypeString);
            jsonObject.put("qclass", QClassString);
            questionJSONArray.put(jsonObject);

        }

        return questionJSONArray;
    }

    /**
     *
     * Decodes the header section
     *
     * @param dataInputStream
     * @return A JSONArray object containing the decoded header.
     * @throws Exception
     */
    private JSONObject decodingHeaderSection (DataInputStream dataInputStream, boolean lengthAvailable) throws Exception {
        // Read length if transport layer protocol is TCP
        int length = 0;
        if (lengthAvailable) {
            String lengthBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                    + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
            length = Integer.parseInt(lengthBinary, 2);
        }


        // Read next two byte, convert them to binary and append them.
        String idBinary = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));

        long id = Integer.parseInt(idBinary, 2);

        // Read next two byte, convert them to binary and append them.
        String flags = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));

        //QR decoding
        String QR = flags.substring(0, 1);
        String QRboolean;
        if(QR.equals("1")) {
            QRboolean = "RESPONSE";
        } else {
            QRboolean = "QUERY";
        }

        //Opcode decoding
        String Opcode = flags.substring(1, 5);
        if (Opcode.equals("0000")) {
            Opcode = "QUERY";
        } else if (Opcode.equals("0001")) {
            Opcode = "IQUERY";
        } else if (Opcode.equals("0002")) {
            Opcode = "STATUS";
        } else {
            Opcode = "UNKNOWN";
        }

        //AA decoding
        String AA = flags.substring(5, 6);
        boolean AAboolean;
        if (AA.equals("1")) {
            AAboolean = true;
        } else {
            AAboolean = false;
        }

        //TC decoding
        String TC = flags.substring(6, 7);
        boolean TCboolean;
        if (TC.equals("1")) {
            TCboolean = true;
        } else {
            TCboolean = false;
        }

        //RD decoding
        String RD = flags.substring(7, 8);
        boolean RDboolean;
        if (RD.equals("1")) {
            RDboolean = true;
        } else {
            RDboolean = false;
        }

        //RA decoding
        String RA = flags.substring(8, 9);
        boolean RAboolean;
        if (RA.equals("1")) {
            RAboolean = true;
        } else {
            RAboolean = false;
        }

        //Z decoding
        String Z = flags.substring(9, 10);

        //AD decoding
        String AD = flags.substring(10, 11);
        boolean ADboolean;
        if (AD.equals("1")) {
            ADboolean = true;
        } else {
            ADboolean = false;
        }

        //
        String CD = flags.substring(11, 12);
        boolean CDboolean;
        if (CD.equals("0")) {
            CDboolean = false;
        } else if (AD.equals("1")) {
            CDboolean = true;
        } else {
            CDboolean = false;
        }

        //RCODE decoding
        String RCODE = flags.substring(12, 16);
        int rCode = Integer.parseInt(RCODE, 2);
        if (rCode == 0) {
            RCODE = "NOERROR";
        } else if (rCode == 1) {
            RCODE = "FERROR";
        } else if (rCode == 2) {
            RCODE = "SFAILURE";
        } else if (rCode == 3) {
            RCODE = "NERROR";
        } else if (rCode == 4) {
            RCODE = "NIMPLEMENTED";
        } else if (rCode == 5) {
            RCODE = "REFUSED";
        } else if ((rCode >= 3841 && rCode <= 4095) || rCode == 65535) {
            RCODE = "RESERVED";
        } else {
            RCODE = "UNKNOWN";
        }

        // Read next two byte, convert them to binary and append them.
        String QDCountString = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int QDCount = Integer.parseInt(QDCountString, 2);

        // Read next two byte, convert them to binary and append them.
        String ANCountString = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int ANCount = Integer.parseInt(ANCountString, 2);

        // Read next two byte, convert them to binary and append them.
        String NSCountString = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int NSCount = Integer.parseInt(NSCountString, 2);

        // Read next two byte, convert them to binary and append them.
        String ARCountString = StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())))
                + StaticMethods.appendZero(Integer.toBinaryString(StaticMethods.unsignByte(dataInputStream.readByte())));
        int ARCount = Integer.parseInt(ARCountString, 2);

        JSONObject headerJSONObject = new JSONObject();
        if (lengthAvailable) {
            headerJSONObject.put("length", length);
        }
        headerJSONObject.put("id", id);
        headerJSONObject.put("qr", QRboolean);
        headerJSONObject.put("opcode", Opcode);
        headerJSONObject.put("aa", AAboolean);
        headerJSONObject.put("ad", ADboolean);
        headerJSONObject.put("tc", TCboolean);
        headerJSONObject.put("rd", RDboolean);
        headerJSONObject.put("ra", RAboolean);
        headerJSONObject.put("cd", CDboolean);
        headerJSONObject.put("rcode", RCODE);
        headerJSONObject.put("qdcount", QDCount);
        headerJSONObject.put("nscount", NSCount);
        headerJSONObject.put("ancount", ANCount);
        headerJSONObject.put("arcount", ARCount);
        return headerJSONObject;
    }


    private StringBuilder getErrorBuffer() {
        return this.errorBuffer;
    }

    @Override
    public boolean checkHeader(PcapPacket p) {
        if (p.hasHeader(new Udp())) {
            Udp udp = p.getHeader(new Udp());
            if (udp.source() == 53 || udp.destination() == 53) {
                return true;
            }
        } else if (p.hasHeader(new Tcp())) {
            Tcp tcp = p.getHeader(new Tcp());
            if (tcp.source() == 53 || tcp.destination() == 53) {
                return true;
            }
        }

        return false;
    }
}