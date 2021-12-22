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
	var address, tokenFilePath string
	var port, index int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.StringVar(&tokenFilePath, "in", "", "path to the token file")
	flag.IntVar(&index, "i", 0, "index of token to send")	
	flag.Parse()
	
	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}

	file, err := ioutil.ReadFile(tokenFilePath)
	if err != nil {
		errLog.Fatal(err)
		return
	}	
	unspentTokens := btd.UnspentTokens{}
 
	err = json.Unmarshal([]byte(file), &unspentTokens)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), unspentTokens.SignedTokens)
	if err != nil {
		errLog.Fatal(err)
		return
	}	

	xT := crypto.UnblindPoint(xbP[index], unspentTokens.BlindingFactors[index])
	sk := crypto.DeriveKey(h2cObj.Hash(), xT, unspentTokens.Headers[index])
	reqData := [][]byte{testMessage}
	reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, reqData)
	contents := [][]byte{unspentTokens.Headers[index], reqBinder}
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
