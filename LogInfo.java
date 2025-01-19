import java.time.LocalDateTime;
import java.util.ArrayList;

public class LogInfo {
    private ArrayList<String> logs;

    public LogInfo() {
        this.logs = new ArrayList<>();
    }

    public void logAction(String action) {
        String timestamp = LocalDateTime.now().toString();
        logs.add(timestamp + " - " + action);
    }

    public void displayLogs() {
        System.out.println("Journal des actions :");
        for (String log : logs) {
            System.out.println(log);
        }
    }
}