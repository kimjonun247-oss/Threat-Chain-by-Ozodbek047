package main
import ("database/sql";"fmt";"net/http")
var db *sql.DB
func h(w http.ResponseWriter, r *http.Request) {
	q := fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", r.URL.Query().Get("id"))
	db.Query(q)
}
