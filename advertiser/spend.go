package main

import (
	"encoding/json"
	"flag"	
	//"fmt"
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
	h2cParamsBytes, err := json.Marshal(cp)
	if err != nil {
		errLog.Fatal(err)
		return
	}

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
		xbP, err := crypto.BatchUnmarshalPoints(
			h2cObj.Curve(),
			unspentTokens.SignedTokens[denom])
		if err != nil {
			errLog.Fatal(err)
			return
		}

		msgs := make([][][]byte, len(xbP))
		tags := make([][][]byte, len(xbP))		
		for i := 0; i < len(xbP); i++ {
			xT := crypto.UnblindPoint(xbP[i], unspentTokens.BlindingFactors[denom][i])
			sk := crypto.DeriveKey(h2cObj.Hash(), xT, headers[i])
			msg := [][]byte{testMsg}
			reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, msg)
			msgs[i] = msg
			tags[i] = [][]byte{headers[i], reqBinder}
			tags[i] = append(tags[i], h2cParamsBytes)
		}
		paidTokens.Headers = append(paidTokens.Headers, headers)
		paidTokens.Tags = append(paidTokens.Tags, tags)
		paidTokens.Messages = append(paidTokens.Messages, msgs)
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
