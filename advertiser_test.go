package btd

import (
	stdcrypto "crypto"		
	crand "crypto/rand"		
	"crypto/elliptic"
	"encoding/base64"	
	"encoding/json"
	"errors"
	"fmt"
	"testing"
    "unsafe"	

	"github.com/kev-liao/challenge-bypass-server/crypto"	
)

// Fakes the sampling of a signing key
func fakeSigningKey(h2cObj crypto.H2CObject) ([]byte, error) {
	k, _, _, err := elliptic.GenerateKey(h2cObj.Curve(), crand.Reader)
	if err != nil {
		return nil, err
	}
	return k, nil
}

// Fakes the procedure of producing commitments for a signing key
func fakeCommitments(key []byte, h2cObj crypto.H2CObject) (*crypto.Point, *crypto.Point, error) {
	_, Gx, Gy, err := elliptic.GenerateKey(h2cObj.Curve(), crand.Reader)
	if err != nil {
		return nil, nil, err
	}

	curve := h2cObj.Curve()
	G := &crypto.Point{Curve: curve, X: Gx, Y: Gy}
	Hx, Hy := curve.ScalarMult(Gx, Gy, key)
	H := &crypto.Point{Curve: curve, X: Hx, Y: Hy}

	return G, H, nil
}

// Combines the above two methods
func fakeKeyAndCommitments(h2cObj crypto.H2CObject) ([]byte, *crypto.Point, *crypto.Point, error) {
	x, err := fakeSigningKey(h2cObj)
	if err != nil {
		return nil, nil, nil, err
	}

	G, H, err := fakeCommitments(x, h2cObj)
	if err != nil {
		return nil, nil, nil, err
	}

	return x, G, H, nil
}

func makeTokenRequest(h2cObj crypto.H2CObject, numTokens int) ([]byte, [][]byte, []*crypto.Point, [][]byte, error) {
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

	contents := make([][][]byte, 1)
	contents[0] = marshaledTokenList
	request := &BlindTokenRequest{
		Type: "Issue",
		Contents: contents,
		Denoms: []int{0}}

	encoded, _ := MarshalRequest(request)
	wrappedRequest := &BlindTokenRequestWrapper{
		Request: encoded,
	}
	
	requestBytes, err := json.Marshal(wrappedRequest)
	if err != nil {
		return nil, nil, nil, nil, err
	}	
	
	return requestBytes, tokens, bP, bF, nil
}

var cp = &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
var h2cObj, _ = cp.GetH2CObj()
var key, G, H, _ = fakeKeyAndCommitments(h2cObj)

func benchmarkMakeTokenRequest(b *testing.B, numTokens int) {
	makeTokenRequest(h2cObj, numTokens)
}

//func BenchmarkAdvertiserTokenRequest100(b *testing.B) {
//	benchmarkMakeTokenRequest(b, 100)
//}

func BenchmarkAdvertiserTokenRequest1000(b *testing.B) {
	benchmarkMakeTokenRequest(b, 1000)
}

//func BenchmarkAdvertiserTokenRequest5000(b *testing.B) {
//	benchmarkMakeTokenRequest(b, 5000)
//}
//
// Takes a long time
//func BenchmarkAdvertiserTokenRequest10000(b *testing.B) {
//	benchmarkMakeTokenRequest(b, 10000)
//}

func TestAdvertiser1000TokenRequestSize(t *testing.T) {
	requestBytes, _, _, _, _ := makeTokenRequest(h2cObj, 1000)
	fmt.Println("1000 token request bytes:", len(requestBytes))
}

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest(h2cObj crypto.H2CObject, numTokens int) (*BlindTokenRequest, [][]byte, []*crypto.Point, [][]byte, error) {
	tokens := make([][]byte, numTokens)
	bF := make([][]byte, len(tokens))
	bP := make([]*crypto.Point, len(tokens))
	for i := 0; i < len(tokens); i++ {
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

	request := &BlindTokenRequest{
		Type:     "Issue",
		Contents: [][][]byte{marshaledTokenList}, // this is [][]byte, not JSON
	}
	return request, tokens, bP, bF, nil
}

var request, heads, bP, bF, _ = makeTokenIssueRequest(h2cObj, 1000)
var response, _ = ApproveTokens(*request, key, "1.1", G, H)
var xbP, _ = crypto.BatchUnmarshalPoints(h2cObj.Curve(), response.Sigs)
func TestAdvertiser1000TokenStorage(t *testing.T) {
	headerBytes := 0
	bFbytes := 0
    xbPbytes := 0
	for i := 0; i < 1000; i++ {
		headerBytes += len(heads[i])
		bFbytes += len(bF[i])
		xbPbytes += int(unsafe.Sizeof(*xbP[i]))
	}
	fmt.Println("Storage for 1k headers:", headerBytes)
	fmt.Println("Storage for 1k blinding factors:", bFbytes)
	fmt.Println("Storage for 1k signed tokens:", xbPbytes)
	fmt.Println("Storage for 1k unspent tokens:", headerBytes + bFbytes + xbPbytes)	
}

// Move function
func recomputeComposites(G, Y *crypto.Point, P, Q []*crypto.Point, hash stdcrypto.Hash, curve elliptic.Curve) (*crypto.Point, *crypto.Point, error) {
	compositeM, compositeZ, _, err := crypto.ComputeComposites(hash, curve, G, Y, P, Q)
	return compositeM, compositeZ, err
}

// XXX
func BenchmarkAdvertiserCheckProof1000(b *testing.B) {
	dleq, _ := crypto.UnmarshalBatchProof(h2cObj.Curve(), response.Proof)
	dleq.G = G
	dleq.H = H
	dleq.M, dleq.Z, _ = recomputeComposites(G, H, bP, xbP, h2cObj.Hash(), h2cObj.Curve())
	dleq.Verify()
}

func TestAdvertiser1000TokenResponseSize(t *testing.T) {
	// Encodes the issue response as a JSON object
	jsonResp, _ := json.Marshal(response)

	// which we then wrap in another layer of base64 to avoid any transit or parsing mishaps
	base64Envelope := make([]byte, base64.StdEncoding.EncodedLen(len(jsonResp)))
	base64.StdEncoding.Encode(base64Envelope, jsonResp)
	fmt.Println("1000 token response bytes:", len(base64Envelope))
}

var testMsg = []byte("test")
var bidSize = 8
var request2, headers, bPs, bFs, _ = makeTokenIssueRequest(h2cObj, bidSize)
var response2, _ = ApproveTokens(*request2, key, "1.1", G, H)
var xbPs, _ = crypto.BatchUnmarshalPoints(h2cObj.Curve(), response2.Sigs)

func BenchmarkAdvertiserMakePayment(b *testing.B) {
	for i := 0; i < bidSize; i++ {
		xT := crypto.UnblindPoint(xbPs[i], bFs[i])
		sk := crypto.DeriveKey(h2cObj.Hash(), xT, headers[i])
		msg := [][]byte{testMsg}
		_ = crypto.CreateRequestBinding(h2cObj.Hash(), sk, msg)
	}
}

// Sign tokens for verifying DLEQ proof
func signTokens(P []*crypto.Point, key []byte) []*crypto.Point {
	Q := make([]*crypto.Point, len(P))
	for i := 0; i < len(Q); i++ {
		Q[i] = crypto.SignPoint(P[i], key)
	}
	return Q
}

func makeTokenRedempRequest(x []byte, G, H *crypto.Point, h2cObj crypto.H2CObject) (*BlindTokenRequest, error) {
	// Client
	request, tokens, bP, bF, err := makeTokenIssueRequest(h2cObj, 1000)
	if err != nil {
		return nil, err
	}

	// Client -> (request) -> Server

	// Server
	// Sign the blind points (x is the signing key)
	marshaledData, err := ApproveTokens(*request, x, "1.1", G, H)
	if err != nil {
		return nil, err
	}

	// Client <- (signed blind tokens) <- Server

	// Client
	// a. Umarshal signed+blinded points
	// XXX: hardcoded curve assumption
	marshaledPoints, marshaledBP := marshaledData.Sigs, marshaledData.Proof
	xbP, err := crypto.BatchUnmarshalPoints(h2cObj.Curve(), marshaledPoints)
	if err != nil {
		return nil, err
	}

	// b. Unmarshal and verify batch proof
	// We need to re-sign all the tokens and re-compute
	dleq, err := crypto.UnmarshalBatchProof(h2cObj.Curve(), marshaledBP)
	if err != nil {
		return nil, err
	}
	dleq.G = G
	dleq.H = H
	Q := signTokens(bP, x)
	dleq.M, dleq.Z, err = recomputeComposites(G, H, bP, Q, h2cObj.Hash(), h2cObj.Curve())
	if err != nil {
		return nil, err
	}
	if !dleq.Verify() {
		return nil, errors.New("Batch proof failed to verify")
	}

	// c. Unblind a point
	xT := crypto.UnblindPoint(xbP[0], bF[0])
	// d. Derive MAC key
	sk := crypto.DeriveKey(h2cObj.Hash(), xT, tokens[0])
	// e. MAC the request binding data
	reqData := [][]byte{[]byte("test")}
	reqBinder := crypto.CreateRequestBinding(h2cObj.Hash(), sk, reqData)
	contents := [][]byte{tokens[0], reqBinder}
	var h2cParamsBytes []byte
	if h2cObj.Method() == "swu" {
		curveParams := &crypto.CurveParams{Curve: "p256", Hash: "sha256", Method: "swu"}
		h2cParamsBytes, err = json.Marshal(curveParams)
		if err != nil {
			return nil, err
		}
		contents = append(contents, h2cParamsBytes)
	}

	redeemRequest := &BlindTokenRequest{
		Type:     "Redeem",
		Contents: [][][]byte{contents},
		Denoms:   []int{0},
	}

	return redeemRequest, nil
}

var redempRequest, _ = makeTokenRedempRequest(key, G, H, h2cObj)
var redeemKeys = [][]byte{key}

func BenchmarkExchangeRedemption(b *testing.B) {
	RedeemToken(*redempRequest, []byte("test"), redeemKeys)
}

func BenchmarkExchangeIssuance(b *testing.B) {
	ApproveTokens(*request, key, "1.1", G, H)	
}
