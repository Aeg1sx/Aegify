import Foundation

class DatabaseService {
    var connectionString: String

    init(connectionString: String) {
        self.connectionString = connectionString
    }

    func getUser(userId: String) -> String {
        let query = "SELECT * FROM users WHERE id = '\(userId)'"
        return executeQuery(query: query)
    }

    func executeQuery(query: String) -> String {
        return query
    }
}

class CommandRunner {
    func runCommand(input: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", input]
        try? process.run()
    }
}

func handleUserInput(input: String) -> String {
    let db = DatabaseService(connectionString: "sqlite:///mydb")
    return db.getUser(userId: input)
}

func executeShell(command: String) {
    let runner = CommandRunner()
    runner.runCommand(input: command)
}
