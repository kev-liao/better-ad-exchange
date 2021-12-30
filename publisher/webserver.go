package main

import (
	"encoding/json"
	"flag"	
	"fmt"
	"io/ioutil"	
	"log"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/kev-liao/challenge-bypass-server"	
)

type PubServer struct {
	ExchangeAddress string
	ExchangePort    int
}

var	(
	testMessage = []byte("test")
	errLog *log.Logger = log.New(os.Stderr, "[publisher] ", log.LstdFlags|log.Lshortfile)
)

func (s *PubServer) tokenHandler(w http.ResponseWriter, r *http.Request) {
    if r.Method != "POST" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }
	
	payment := &btd.TokenPayment{}
	err := json.NewDecoder(r.Body).Decode(&payment)
	if err != nil {
		log.Fatal(err)
		return
    }

	// TODO: Check that tokens add up to price
	
	// Redeem tokens with ad exchange
	redeemRequest := &btd.BlindTokenRequest{
		Type: "Redeem",
		Contents: payment.Tokens.Contents}
	
	encoded, _ := btd.MarshalRequest(redeemRequest)
	wrappedRequest := &btd.BlindTokenRequestWrapper{
		Request: encoded,
		Message: string(testMessage)}
	
	requestBytes, err := json.Marshal(wrappedRequest)
	if err != nil {
		errLog.Fatal(err)
		return		
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", s.ExchangeAddress, strconv.Itoa(s.ExchangePort)))
	if err != nil {
		errLog.Fatal(err)
		return
	}	

	_, err = conn.Write(requestBytes)
	if err != nil {
		errLog.Fatal(err)
		return		
	}

	redeemResponse, err := ioutil.ReadAll(conn)
	if err != nil {
		errLog.Fatal(err)
		return		
	}	

	if string(redeemResponse) != "success" {
		w.Write([]byte("0"))
	} else {
		w.Write([]byte("1"))		
	}

	return
}

func main() {
	var address string
	var port int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.Parse()

	srv := &PubServer{}
	srv.ExchangeAddress = address
	srv.ExchangePort = port
	
    http.HandleFunc("/tokens", srv.tokenHandler)
	
    fmt.Printf("Starting publisher server at port 8081\n")
    if err := http.ListenAndServe(":8081", nil); err != nil {
        log.Fatal(err)
    }	
}
