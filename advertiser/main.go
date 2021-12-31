package main

import (
	stdcrypto "crypto"	
	"crypto/elliptic"	
	"encoding/base64"	
	"encoding/json"
	"errors"	
	"flag"	
	"fmt"
	"io/fs"		
	"io/ioutil"
	"log"
	"path/filepath"		
	"net"
	"os"
	"strconv"	

	"github.com/kev-liao/challenge-bypass-server"	
	"github.com/kev-liao/challenge-bypass-server/crypto"
)

var	(
	ErrInvalidProof    = errors.New("Batch proof failed to verify")	
	errLog *log.Logger = log.New(os.Stderr, "[advertiser] ", log.LstdFlags|log.Lshortfile)
)

func getCommPoints(commFilePath string) (*crypto.Point, *crypto.Point, error) {
	GBytes, HBytes, err := crypto.ParseCommitmentFile(commFilePath)
	if err != nil {
		return nil, nil, err
	}

	G := &crypto.Point{Curve: elliptic.P256(), X: nil, Y: nil}
	err = G.Unmarshal(G.Curve, GBytes)
	if err != nil {
		return nil, nil, err
	}
	H := &crypto.Point{Curve: elliptic.P256(), X: nil, Y: nil}
	err = H.Unmarshal(H.Curve, HBytes)
	if err != nil {
		return nil, nil, err
	}
	
	return G, H, nil
}

func makeTokenRequest(h2cObj crypto.H2CObject, denom, numTokens int) ([]byte, [][]byte, []*crypto.Point, [][]byte, error) {
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

	// XXX
	contents := make([][][]byte, 1)
	contents[0] = marshaledTokenList
	request := &btd.BlindTokenRequest{
		Type: "Issue",
		Contents: contents,
		Denoms: []int{denom}}

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

func decodeTokenResponse(encodedResponse []byte) (*btd.IssuedTokenResponse, error) {
	responseBytes := make([]byte, base64.StdEncoding.DecodedLen(len(encodedResponse)))
	n, err := base64.StdEncoding.Decode(responseBytes, encodedResponse)
    if err != nil {
		return nil, err
    }	
	response := &btd.IssuedTokenResponse{}
	err = json.Unmarshal(responseBytes[:n], response)
	if err != nil {
		return nil, err
	}
	return response, nil
}

func recomputeComposites(G, Y *crypto.Point, P, Q []*crypto.Point, hash stdcrypto.Hash, curve elliptic.Curve) (*crypto.Point, *crypto.Point, error) {
	compositeM, compositeZ, _, err := crypto.ComputeComposites(hash, curve, G, Y, P, Q)
	return compositeM, compositeZ, err
}

func find(root, ext string) []string {
   var a []string
   filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
      if e != nil { return e }
      if filepath.Ext(d.Name()) == ext {
         a = append(a, s)
      }
      return nil
   })
   return a
}

func main() {
	var err error
	var address, commDir, denomFile, tokenFile string
	var port int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.StringVar(&commDir, "comm", "", "path to the commitment file")
	flag.StringVar(&denomFile, "denom", "", "path to the denom file")	
	flag.StringVar(&tokenFile, "out", "", "path to the token file")
	flag.Parse()

	Gs := []*crypto.Point{}
	Hs := []*crypto.Point{}
	for _, commFile := range find(commDir, ".comm") {
		G, H, err := getCommPoints(commFile)
		if err != nil {
			errLog.Fatal(err)
			return
		}
		Gs = append(Gs, G)
		Hs = append(Hs, H)
	}

	cp := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
	h2cObj, err := cp.GetH2CObj()
	if err != nil {
		errLog.Fatal(err)
		return
	}	

	file, err := ioutil.ReadFile(denomFile)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	var denoms []int
	err = json.Unmarshal([]byte(file), &denoms)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	var unspentToks = &btd.UnspentTokens{}
	for denom, numTokens := range denoms {
		requestBytes, headers, bP, bF, err := makeTokenRequest(h2cObj, denom, numTokens)
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

		response, err := decodeTokenResponse(encodedResponse)
		if err != nil {
			errLog.Fatal(err)
			return
		}	

		xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), response.Sigs)
		if err != nil {
			errLog.Fatal(err)
			return
		}

		dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), response.Proof)
		if err != nil {
			errLog.Fatal(err)
			return
		}
		dleq.G = Gs[denom]
		dleq.H = Hs[denom]
		dleq.M, dleq.Z, err = recomputeComposites(Gs[denom], Hs[denom], bP, xbP, h2cObj.Hash(), h2cObj.Curve())
		if !dleq.Verify() {
			errLog.Fatal(ErrInvalidProof)
			return
		}

		unspentToks.Headers = append(unspentToks.Headers, headers)
		unspentToks.BlindingFactors = append(unspentToks.BlindingFactors, bF)
		unspentToks.SignedTokens = append(unspentToks.SignedTokens, response.Sigs)
	}

	file, err = json.MarshalIndent(unspentToks, "", " ")
	if err != nil {
		errLog.Fatal(err)
		return
	}	

	err = ioutil.WriteFile(tokenFile, file, 0644)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	return
}
