package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"golang.org/x/net/http2"
)

var (
	port = flag.String("port", ":8081", "Arbitrary config file")
)

const ()

func healthz(w http.ResponseWriter, r *http.Request) {
	fmt.Println("healthcheck")
	fmt.Fprint(w, "ok")
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("get")
	fmt.Fprint(w, "ok")
}

func posthandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()
	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/healthz").HandlerFunc(healthz)
	router.Methods(http.MethodGet).Path("/get").HandlerFunc(gethandler)
	router.Methods(http.MethodPost).Path("/post").HandlerFunc(posthandler)

	var err error

	server := &http.Server{
		Addr:    *port,
		Handler: router,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServe()
	fmt.Printf("Unable to start Server %v", err)

}
