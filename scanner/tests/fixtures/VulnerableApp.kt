import java.sql.DriverManager
import java.sql.Connection

class UserController(private val dbUrl: String) {
    fun getUser(userId: String): String {
        val conn = DriverManager.getConnection(dbUrl)
        val stmt = conn.createStatement()
        val query = "SELECT * FROM users WHERE id = '$userId'"
        val rs = stmt.executeQuery(query)
        return rs.getString(1)
    }

    fun deleteUser(userId: String) {
        val conn = DriverManager.getConnection(dbUrl)
        val stmt = conn.createStatement()
        stmt.executeUpdate("DELETE FROM users WHERE id = '$userId'")
    }

    fun runCommand(cmd: String) {
        Runtime.getRuntime().exec(cmd)
    }
}

fun handleRequest(input: String): String {
    val controller = UserController("jdbc:mysql://localhost/db")
    return controller.getUser(input)
}

fun executeCommand(command: String) {
    val controller = UserController("jdbc:mysql://localhost/db")
    controller.runCommand(command)
}
