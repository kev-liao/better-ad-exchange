package main

import (
	stdcrypto "crypto"	
	"crypto/elliptic"	
	"encoding/base64"	
	"encoding/json"
	"errors"	
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

func generateTokenRequest(h2cObj crypto.H2CObject, numTokens int) ([]byte, [][]byte, []*crypto.Point, [][]byte,error) {
	tokens := make([][]byte, numTokens)
	bF := make([][]byte, numTokens)
	bP := make([]*crypto.Point, numTokens)
	for i := 0; i < numTokens; i++ {
		token, bPoint, bFactor, err := crypto.CreateBlindToken(h2cObj)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		tokens[i] = token
		bP[i] = bPoint
		bF[i] = bFactor
	}
	marshaledTokenList, err := crypto.BatchMarshalPoints(bP)
	if err != nil {
		return nil, nil, nil, nil, err
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
		return nil, nil, nil, nil, err
	}	
	
	return requestBytes, tokens, bP, bF, nil
}

func recomputeComposites(G, Y *crypto.Point, P, Q []*crypto.Point, hash stdcrypto.Hash, curve elliptic.Curve) (*crypto.Point, *crypto.Point, error) {
	compositeM, compositeZ, _, err := crypto.ComputeComposites(hash, curve, G, Y, P, Q)
	return compositeM, compositeZ, err
}

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

	GBytes, HBytes, err := crypto.ParseCommitmentFile(commFilePath)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	G := &crypto.Point{Curve: elliptic.P256(), X: nil, Y: nil}
	err = G.Unmarshal(G.Curve, GBytes)
	if err != nil {
		errLog.Fatal(err)
		return		
	}
	H := &crypto.Point{Curve: elliptic.P256(), X: nil, Y: nil}
	err = H.Unmarshal(H.Curve, HBytes)
	if err != nil {
		errLog.Fatal(err)
		return
	}	
	
	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}

	//request, tokens, bP, bF, err := makeTokenIssueRequest(h2cObj)
	//if err != nil {
	//	return nil, err
	//}

	requestBytes, _, bP, _, err := generateTokenRequest(h2cObj, numTokens)
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
	response := &btd.IssuedTokenResponse{}
	err = json.Unmarshal(responseBytes[:n], response)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	marshaledPoints, marshaledBP := response.Sigs, response.Proof
	xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), marshaledPoints)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), marshaledBP)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	dleq.G = G
	dleq.H = H
	dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, xbP, h2cObj.Hash(), h2cObj.Curve())
	if !dleq.Verify() {
		errLog.Fatal(errors.New("Batch proof failed to verify"))
		return
	}	
	
	return
}
