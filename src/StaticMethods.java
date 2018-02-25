import org.apache.commons.validator.routines.InetAddressValidator;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.regex.Pattern;

public class StaticMethods {

    /**
     * Appends "0" at the beginning of the given binary string up to 8 bits.
     * @param binary The binary String object to append "0" with.
     * @return The binary String object.
     */
    public static String appendZero(String binary) {
        String result = binary;
        while (result.length() < 8) {
            result = "0" + result;
        }

        return result;
    }

    /**
     * Converts a signed byte into a unsigned byte.
     * @param signedByte The signed byte to be converted.
     * @return An integer of the unsigned byte.
     */
    public static int unsignByte(byte signedByte) {
        return signedByte & 0xFF;
    }


    public static String convertIpAddressByteToString(byte[] ipAddressBytes) throws Exception {
        //Converts bytes to hexademical
        String ipAddress = "";
        for(int i = 0; i < ipAddressBytes.length; i ++) {
            ipAddress += unsignByte(ipAddressBytes[i]) + ".";
        }

        // Removes last colon.
        ipAddress = ipAddress.substring(0, ipAddress.length() - 1);

        if (!isValidIP(ipAddress)) {
            throw new Exception(ipAddress + " is not valid.");
        } else {
            return ipAddress;
        }
    }

    /**
     * Appends two JSONObject.
     *
     * @param j1 First JSONObject
     * @param j2 Second JSONObject
     * @return The appended JSONObject
     * @throws JSONException If JSON goes wrong.
     */
    public static JSONObject appendJSONObject(JSONObject j1, JSONObject j2) throws JSONException {
        if (j1 == null) {
            return j2;
        } else if (j2 == null) {
            return j1;
        }

        JSONObject merged = j1;

        for (String key : JSONObject.getNames(j2)) {
            merged.put(key, j2.get(key));
        }

        return merged;
    }

    /**
     * Saves the JSONObject to a JSON file with the given file name.
     * @param jsonObject The JSONObject to be outputted.
     * @param fileName The name for the file.
     * @throws IOException When file creating/writing goes wrong.
     * @throws JSONException When JSON exception.
     */
    public static void saveJSONToFile(JSONObject jsonObject, String fileName) throws IOException, JSONException {
        File file = new File(fileName);
        file.createNewFile();
        FileWriter fileWriter = new FileWriter(file);
        fileWriter.write(jsonObject.toString(4));
        fileWriter.flush();
        fileWriter.close();
    }

    public static String convertMacAddressByteToString(byte[] macAddressBytes) throws Exception {
        //Converts bytes to hexademical
        String macAddress = "";
        for(int i = 0; i < macAddressBytes.length; i ++) {
            macAddress += Integer.toHexString(unsignByte(macAddressBytes[i])) + ":";
        }

        // Removes last colon.
        macAddress = macAddress.substring(0, macAddress.length() - 1);

        if (!isValidMAC(macAddress)) {
            throw new Exception(macAddress + " is not valid.");
        } else {
            return macAddress;
        }

    }

    /**
     * Validates IPv4 address.
     * @param ipAddress  A string to validate if it is is a valid IPv4 address.
     * @return boolean indicating whether given string is a valid IPv4 address.
     */
    public static boolean isValidIP(String ipAddress) {
        return InetAddressValidator.getInstance().isValidInet4Address(ipAddress);

    }

    /**
     * Validates MAC address using a regular expression.
     * @param macAddress A string to validate if it is a valid MAC address.
     * @return boolean indicating whether given string is a valid MAC address.
     */
    public static boolean isValidMAC(String macAddress) {
        String Regex = "^((([0-9A-Fa-f]{2}|[0-9A-Fa-f]):){5})([0-9A-Fa-f]{2}|[0-9A-Fa-f])$";

        Pattern pattern = Pattern.compile(Regex);
        return pattern.matcher(macAddress).matches();
    }


}
