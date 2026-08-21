package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

// SQL Injection
func getUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
	defer rows.Close()
	fmt.Fprintf(w, "result: %v", rows)
}

// Command Injection
func ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", "-c", "1", host)
	output, _ := cmd.Output()
	fmt.Fprintf(w, "%s", output)
}

// XSS via direct write
func greet(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func validateInput(data string) string {
	if data == "" {
		panic("empty input")
	}
	return data
}

func queryDatabase(id string) *sql.Rows {
	rows, _ := db.Query("SELECT * FROM users WHERE id = " + id)
	return rows
}

func getUser2(w http.ResponseWriter, r *http.Request) {
	id := validateInput(r.URL.Query().Get("id"))
	rows := queryDatabase(id)
	defer rows.Close()
}

func main() {
	http.HandleFunc("/users", getUser)
	http.HandleFunc("/ping", ping)
	http.HandleFunc("/greet", greet)
	http.HandleFunc("/users2", getUser2)
	http.ListenAndServe(":8080", nil)
}
