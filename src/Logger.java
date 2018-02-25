import org.json.JSONException;
import org.json.JSONObject;

/**
 * Logging class used to logs messages.
 */

public class Logger {

    //The simple "database" for now.
    private StringBuilder logs;
    private static Logger instance;

    private Logger() {
        logs = new StringBuilder();
    }

    public void logError(String errorMessage) {
        logs.append("ERROR:" + errorMessage + System.lineSeparator());
    }

    public void logNotice(String noticeMessage) {
        logs.append("notice: " + noticeMessage + System.lineSeparator());
    }

    @Override
    public String toString() {
        return logs.toString();
    }

    public JSONObject toJSON() throws JSONException {
        String[] lines = logs.toString().split("\r\n");
        JSONObject logsJSONObject = new JSONObject();
        for (int i = 0; i < lines.length; i ++) {
            logsJSONObject.put(String.valueOf(i), lines[i]);
        }

        return logsJSONObject;
    }

    public static synchronized Logger getInstance() {
        if (instance == null) {
            instance = new Logger();
        }

        return instance;
    }

}
