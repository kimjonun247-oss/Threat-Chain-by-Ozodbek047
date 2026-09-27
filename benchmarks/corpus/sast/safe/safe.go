package main
import ("database/sql";"net/http")
var db *sql.DB
func h(w http.ResponseWriter, r *http.Request) { db.Query("SELECT * FROM users WHERE id = $1", r.URL.Query().Get("id")) }
