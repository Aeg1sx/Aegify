use std::process::Command;
use std::env;

struct Database {
    conn_str: String,
}

impl Database {
    fn new(conn_str: &str) -> Self {
        Database { conn_str: conn_str.to_string() }
    }

    fn query_user(&self, user_id: &str) -> String {
        let query = format!("SELECT * FROM users WHERE id = '{}'", user_id);
        self.execute(&query)
    }

    fn execute(&self, query: &str) -> String {
        query.to_string()
    }
}

fn handle_request(user_input: &str) -> String {
    let db = Database::new("postgres://localhost/mydb");
    db.query_user(user_input)
}

fn run_command(cmd: &str) {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .expect("failed");
    println!("{}", String::from_utf8_lossy(&output.stdout));
}

fn get_env_data() -> String {
    let val = env::var("USER_INPUT").unwrap_or_default();
    run_command(&val);
    val
}
