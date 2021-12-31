package main

import (
	"encoding/json"
	"flag"	
	"io/ioutil"
	"log"	
	"os"

	"github.com/kev-liao/challenge-bypass-server"	
	"github.com/kev-liao/challenge-bypass-server/crypto"
)

var	(
	testMsg = []byte("test")
	errLog *log.Logger = log.New(os.Stderr, "[advertiser] ", log.LstdFlags|log.Lshortfile)
)

func main() {
	var err error
	var unspentTokenFile, paidTokenFile string

	flag.StringVar(&unspentTokenFile, "in", "", "path to unspent token file")
	flag.StringVar(&paidTokenFile, "out", "", "path to paid token file")
	flag.Parse()

	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}
	//h2cParamsBytes, err := json.Marshal(cp)
	//if err != nil {
	//	errLog.Fatal(err)
	//	return
	//}

	file, err := ioutil.ReadFile(unspentTokenFile)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	unspentTokens := &btd.UnspentTokens{}
	err = json.Unmarshal([]byte(file), &unspentTokens)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	paidTokens := &btd.PaidTokens{}
	for denom, headers := range unspentTokens.Headers {
		// Pop the top signed token
		signedTok := [][]byte{unspentTokens.SignedTokens[denom][0]}
		// Pop the top header
		header := headers[0]
		// Pop the top blinding factor		
		bF := unspentTokens.BlindingFactors[denom][0]		
		xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), signedTok)
		if err != nil {
			errLog.Fatal(err)
			return
		}

		xT := crypto.UnblindPoint(xbP[0], bF)
		sk := crypto.DeriveKey(h2cObj.Hash(), xT, header)
		msg := [][]byte{testMsg}
		reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, msg)
		// XXX: h2cParams are redundant
		//contents := [][]byte{header, reqBinder, h2cParamsBytes}
		contents := [][]byte{header, reqBinder}
		paidTokens.Contents = append(paidTokens.Contents, contents)
		paidTokens.Messages = append(paidTokens.Messages, msg)
	}

	file, err = json.MarshalIndent(paidTokens, "", " ")
	if err != nil {
		errLog.Fatal(err)
		return
	}	

	err = ioutil.WriteFile(paidTokenFile, file, 0644)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	return
}
