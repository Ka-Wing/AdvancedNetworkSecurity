import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.Set;

/**
 * The simplified database, implemented with a singleton pattern, to store valid IP-to-MAC allocations.
 */

public class DAIDatabase {

    //The simple "database" for now.
    private HashMap<String, String> binding;
    private static DAIDatabase instance;

    private DAIDatabase() {
        binding = new HashMap<>();
    }

    public String getValue(String key) {
        return binding.get(key);
    }

    public String setValue(String key, String value) {
        return binding.put(key, value);
    }

    public Set<String> getKeys() {
        return binding.keySet();
    }

    public void loadConfiguration(String file) throws Exception {
        BufferedReader br = new BufferedReader(new FileReader(new File(file)));

        String line;
        int lineNumber = 1;

        while((line = br.readLine()) != null) {
            String[] binding = line.split(" ");
            if (binding.length != 2 || !StaticMethods.isValidIP(binding[0]) || !StaticMethods.isValidMAC(binding[1])) {
                throw new Exception("Configuration file format error at line " + lineNumber + ".");
            }

            getInstance().setValue(binding[0], binding[1]);
            lineNumber ++;
        }
    }

    public static synchronized DAIDatabase getInstance() {
        if (instance == null) {
            instance = new DAIDatabase();
        }

        return instance;
    }

}
