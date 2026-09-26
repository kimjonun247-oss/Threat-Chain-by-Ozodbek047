package main
import ("net/http";"os/exec")
func h(w http.ResponseWriter, r *http.Request) {
	exec.Command("sh", "-c", "ping "+r.URL.Query().Get("host")).Run()
}
