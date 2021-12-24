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
	testMessage = []byte("test")
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

	file, err := ioutil.ReadFile(unspentTokenFile)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	unspentTokens := make(map[int]*btd.UnspentTokens)
	err = json.Unmarshal([]byte(file), &unspentTokens)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	paidTokens := make(map[int]*btd.PaidTokens)
	for denom, tokens := range unspentTokens {
		xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), tokens.SignedTokens)
		if err != nil {
			errLog.Fatal(err)
			return
		}
		h2cParamsBytes, err := json.Marshal(cp)
		if err != nil {
			errLog.Fatal(err)
			return
		}
		tags := make([][][]byte, len(tokens.Headers))
		messages := make([][][]byte, len(tokens.Headers))
		for i := 0; i < len(tokens.Headers); i++ {
			xT := crypto.UnblindPoint(xbP[i], tokens.BlindingFactors[i])
			sk := crypto.DeriveKey(h2cObj.Hash(), xT, tokens.Headers[i])
			messages[i] = [][]byte{testMessage}
			reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, messages[i])
			tags[i] = [][]byte{tokens.Headers[i], reqBinder}
			tags[i] = append(tags[i], h2cParamsBytes)
		}
		paidTokens[denom] = &btd.PaidTokens{
			Denom: denom,
			Headers: tokens.Headers,
			Tags: tags,
			Messages: messages}
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
