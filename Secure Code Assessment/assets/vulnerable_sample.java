import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import java.security.MessageDigest;
import java.io.File;
import java.io.FileReader;
import javax.servlet.http.HttpServletRequest;

public class VulnerableApp {

    // HARDCODED CREDENTIALS
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "AdminSecretPass2026!";
    private static final String PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC...\n-----END PRIVATE KEY-----";

    public void authenticateUser(HttpServletRequest request) {
        String username = request.getParameter("username");
        String pass = request.getParameter("password");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/appdb", DB_USER, DB_PASS);
            
            // SQL INJECTION
            Statement stmt = conn.createStatement();
            String sql = "SELECT * FROM users WHERE user='" + username + "' AND password='" + pass + "'";
            ResultSet rs = stmt.executeQuery(sql); // Vulnerable query execution

            // WEAK HASHING (SHA-1)
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(pass.getBytes());

        } catch (Exception e) {
            e.printStackTrace(); // SENSITIVE INFORMATION EXPOSURE VIA STACK TRACE
        }
    }

    public void executeCommand(String userPath) {
        try {
            // COMMAND INJECTION
            Runtime runtime = Runtime.getRuntime();
            runtime.exec("sh -c /usr/bin/process_file " + userPath);
            
            // PATH TRAVERSAL / INSECURE FILE HANDLING
            File file = new File("/var/app/data/" + userPath);
            FileReader fr = new FileReader(file);

        } catch (Exception e) {
            System.out.println("Error processing file: " + e.getMessage());
        }
    }
}
