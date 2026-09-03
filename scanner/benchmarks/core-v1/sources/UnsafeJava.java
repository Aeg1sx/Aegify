import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public final class UnsafeJava {
    public Object unsafeSql(HttpServletRequest request, Statement statement) throws Exception {
        String id = request.getParameter("id");
        return statement.executeQuery("SELECT * FROM users WHERE id = " + id);
    }

    public Process unsafeCommand(HttpServletRequest request) throws Exception {
        String host = request.getParameter("host");
        return Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
