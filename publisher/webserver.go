package main

import (
	"fmt"
	"log"
	"net/http"
)

func tokenHandler(w http.ResponseWriter, r *http.Request) {
    if err := r.ParseForm(); err != nil {
        fmt.Fprintf(w, "ParseForm() err: %v", err)
        return
    }
	price := r.FormValue("price")	
    tokens := r.FormValue("tokens")
	
	fmt.Println(price)
	fmt.Println(tokens)
	// TODO: Redeem tokens with ad exchange	
	w.Write([]byte("<b>Tokens accepted.</b>"))
}

func main() {
    http.HandleFunc("/tokens", tokenHandler)	
	
    fmt.Printf("Starting publisher server at port 8081\n")
    if err := http.ListenAndServe(":8081", nil); err != nil {
        log.Fatal(err)
    }	
}
