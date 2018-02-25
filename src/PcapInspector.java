import org.jnetpcap.Pcap;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;
import org.jnetpcap.util.PcapPacketArrayList;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class PcapInspector {

    private List<Module> modules;
    private String MacToIPConfigurationFile;
    private String pcapFile;
    private String jsonOutputFilePath;
    private StringBuilder errorBuffer;

    public PcapInspector(String configurationFile, String pcapFile, String jsonOutputFilePath) throws Exception {
        this.MacToIPConfigurationFile = configurationFile;
        this.pcapFile = pcapFile;
        this.jsonOutputFilePath = jsonOutputFilePath;
        this.errorBuffer = new StringBuilder();

        modules = new ArrayList<>();
        modules.add(new ARPInspection(configurationFile));
        modules.add(new DNSParser());
    }

    public void run() throws Exception {

        StringBuilder errorBuffer = new StringBuilder();
        Pcap pcap = Pcap.openOffline(pcapFile, errorBuffer);

        // If opening the file fails.
        if (pcap == null) {
            throw new Exception(errorBuffer.toString());
        }

        PcapPacketHandler<PcapPacketArrayList> jPacketHandler =
                (pcapPacket, pcapPackets) -> pcapPackets.add(pcapPacket);

        try {
            // Retrieve all packets in the pcap file and puts the packets in a PcapPacketArrayList.
            PcapPacketArrayList packets = new PcapPacketArrayList();
            pcap.loop(-1, jPacketHandler, packets);
            int index = 1; // Index of the packet being read when looping through all packets.

            // JSONObject with all packets.
            JSONObject packetsJSONObject = new JSONObject();

            // Statistics variables
            int parsingSuccessful = 0;
            int parsingFailed = 0;

            for (PcapPacket packet : packets) {
                try {
                    //JSONObject for one packet
                    JSONObject packetJSONObject = new JSONObject();
                    for (Module m: modules) {
                        packetJSONObject = StaticMethods.appendJSONObject(packetJSONObject, m.inspect(packet));
                    }

                    packetsJSONObject.put("packet_" + index, packetJSONObject);
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
            StaticMethods.saveJSONToFile(packetsJSONObject, this.jsonOutputFilePath);
            System.out.println("File saved to " + this.jsonOutputFilePath);

        } catch (Exception e) {
            System.out.println(e.getMessage());
        } finally {
            pcap.close();
        }

    }

    public static void main(String[] args) throws Exception {
        String configurationFilePath = args[0];
        String inputPcapFilePath = args[1];
        String outputJSONFilePath = args[2];

        configurationFilePath = "C:\\Users\\kw\\Dropbox\\TU Delft\\Y2\\Q3\\CS4115 Advanced Network Security\\Project 2\\config.txt";
        inputPcapFilePath = "C:\\Users\\kw\\Dropbox\\TU Delft\\Y2\\Q3\\CS4115 Advanced Network Security\\Project 2\\pcap\\arpdns1.pcap";
        outputJSONFilePath = "C:\\Users\\kw\\Dropbox\\TU Delft\\Y2\\Q3\\CS4115 Advanced Network Security\\Project 2\\json.json";

        System.out.println(configurationFilePath);
        System.out.println(inputPcapFilePath);
        System.out.println(outputJSONFilePath);

        PcapInspector pcapInspector = new PcapInspector(configurationFilePath, inputPcapFilePath, outputJSONFilePath);
        pcapInspector.run();
    }

}
