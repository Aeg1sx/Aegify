import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class VulnerableApp {

    private Connection getConnection() throws Exception {
        return DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
    }

    // SQL Injection
    public void getUser(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String userId = request.getParameter("id");
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
    }

    // Command Injection
    public void ping(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // Internal call chain
    private String validateInput(String data) {
        if (data == null || data.isEmpty()) {
            throw new IllegalArgumentException("empty");
        }
        return data.trim();
    }

    private ResultSet queryDatabase(String id) throws Exception {
        Connection conn = getConnection();
        Statement stmt = conn.createStatement();
        return stmt.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public void getUser2(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String id = validateInput(request.getParameter("id"));
        ResultSet rs = queryDatabase(id);
    }
}
