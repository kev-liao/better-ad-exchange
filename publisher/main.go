package main

import (
	"encoding/json"
	"flag"	
	"fmt"
	"io/ioutil"
	"log"	
	"net"
	"os"
	"strconv"	

	"github.com/kev-liao/challenge-bypass-server"	
	"github.com/kev-liao/challenge-bypass-server/crypto"
)

var	(
	testMessage = []byte("test")
	errLog *log.Logger = log.New(os.Stderr, "[publisher] ", log.LstdFlags|log.Lshortfile)
)

func main() {
	var err error
	var address string
	var commFilePath string	
	var port, numTokens int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.IntVar(&numTokens, "n", 10, "number of tokens to request")
	flag.StringVar(&commFilePath, "comm", "", "path to the commitment file")	
	flag.Parse()
	
	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}

	// TODO: Need xbP, bF, tokens
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	sk := crypto.DeriveKey(h2cObj.Hash(), xT, tokens[0])
	reqData := [][]byte{testMessage}
	reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, reqData)
	contents := [][]byte{tokens[0], reqBinder}
	h2cParamsBytes, err := json.Marshal(cp)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	contents = append(contents, h2cParamsBytes)
	redeemRequest := &btd.BlindTokenRequest{
		Type:     "Redeem",
		Contents: contents,
	}

	encoded, _ := btd.MarshalRequest(redeemRequest)
	wrappedRequest := &btd.BlindTokenRequestWrapper{
		Request: encoded,
		Message: string(testMessage),
	}
	
	requestBytes, err := json.Marshal(wrappedRequest)
	if err != nil {
		errLog.Fatal(err)
		return		
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%s", address, strconv.Itoa(port)))
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

	fmt.Println(string(redeemResponse))
	
	return
}
