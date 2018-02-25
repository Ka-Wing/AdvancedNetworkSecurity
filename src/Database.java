import java.util.HashMap;

/**
 * The (for now) simplified database, implemented with a singleton pattern.
 */

public class Database {

    //The simple "database" for now.
    private HashMap<String, String> binding;
    private static Database instance;

    private Database() {
        binding = new HashMap<>();
    }

    public String getValue(String key) {
        return binding.get(key);
    }

    public String setValue(String key, String value) {
        return binding.put(key, value);
    }

    public static synchronized Database getInstance() {
        if (instance == null) {
            instance = new Database();
        }

        return instance;
    }

}
