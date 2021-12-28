package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	
	"github.com/kev-liao/challenge-bypass-server"	
)

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	winResponse := &btd.FwdWinResponse{}
	err := json.NewDecoder(r.Body).Decode(&winResponse)	
	if err != nil {
		log.Fatal(err)
		return
    }		
	fmt.Println(winResponse)

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
