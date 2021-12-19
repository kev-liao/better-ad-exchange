package main

import (
	"encoding/base64"	
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

var	errLog *log.Logger = log.New(os.Stderr, "[advertiser] ", log.LstdFlags|log.Lshortfile)

func generateTokenRequest(h2cObj crypto.H2CObject, numTokens int) ([]byte, error) {
	tokens := make([][]byte, numTokens)
	bF := make([][]byte, numTokens)
	bP := make([]*crypto.Point, numTokens)
	for i := 0; i < numTokens; i++ {
		token, bPoint, bFactor, err := crypto.CreateBlindToken(h2cObj)
		if err != nil {
			return nil, err
		}
		tokens[i] = token
		bP[i] = bPoint
		bF[i] = bFactor
	}
	marshaledTokenList, err := crypto.BatchMarshalPoints(bP)
	if err != nil {
		return nil, err
	}

	request := &btd.BlindTokenRequest{
		Type:     "Issue",
		Contents: marshaledTokenList,
	}

	encoded, _ := btd.MarshalRequest(request)
	wrappedRequest := &btd.BlindTokenRequestWrapper{
		Request: encoded,
	}
	
	requestBytes, err := json.Marshal(wrappedRequest)
	if err != nil {
		return nil, err
	}	
	
	return requestBytes, nil
}

func main() {
	var err error
	var address string
	//var commFilePath string	
	var port, numTokens int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.IntVar(&numTokens, "n", 10, "number of tokens to request")
	//flag.StringVar(&commFilePath, "comm", "", "path to the commitment file")	
	flag.Parse()

	//GBytes, HBytes, err := crypto.ParseCommitmentFile(commFilePath)
	//if err != nil {
	//	errLog.Fatal(err)
	//	return
	//}
	//
	//G, H, err = crypto.RetrieveCommPoints(GBytes, HBytes, cnf.signKey)
	//if err != nil {
	//	errLog.Fatal(err)
	//	return
	//}	
	
	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}

	requestBytes, err := generateTokenRequest(h2cObj, numTokens)
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

	encodedResponse, err := ioutil.ReadAll(conn)
    if err != nil {
		errLog.Fatal(err)
		return		
    }

	responseBytes := make([]byte, base64.StdEncoding.DecodedLen(len(encodedResponse)))
	n, err := base64.StdEncoding.Decode(responseBytes, encodedResponse)
    if err != nil {
		errLog.Fatal(err)
		return		
    }	
	fmt.Println(n)

	response := &btd.IssuedTokenResponse{}
	err = json.Unmarshal(responseBytes[:n], response)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	marshaledPoints, marshaledBP := response.Sigs, response.Proof
	//xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), marshaledPoints)
	_, err = crypto.BatchUnmarshalPoints(h2cObj.Curve(), marshaledPoints)	
	if err != nil {
		errLog.Fatal(err)
		return
	}

	dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), marshaledBP)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	fmt.Println(dleq)
	//dleq.G = G
	//dleq.H = H
	//Q := signTokens(bP, x)
	//dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, Q, h2cObj.Hash(), h2cObj.Curve())
	//if err != nil {
	//	errLog.Fatal(err)
	//	return
	//}
	//if !dleq.Verify() {
	//	errLog.Fatal(err)
	//	return
	//}
	
	return
}
