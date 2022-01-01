package btd

import (
	stdcrypto "crypto"		
	crand "crypto/rand"		
	"crypto/elliptic"
	"encoding/json"	
	"testing"

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

func advertiserTokenRequest(b *testing.B, h2cObj crypto.H2CObject, numTokens int) ([]byte, [][]byte, []*crypto.Point, [][]byte, error) {
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

func BenchmarkAdvertiserTokenRequest100(b *testing.B) {
	advertiserTokenRequest(b, h2cObj, 100)
}

//func BenchmarkAdvertiserTokenRequest1000(b *testing.B) {
//	advertiserTokenRequest(b, h2cObj, 1000)
//}
//
//func BenchmarkAdvertiserTokenRequest5000(b *testing.B) {
//	advertiserTokenRequest(b, h2cObj, 5000)
//}
//
// Takes a long time
//func BenchmarkAdvertiserTokenRequest10000(b *testing.B) {
//	benchmarkAdvertiserTokenRequest(b, h2cObj, 10000)
//}

// Generates a small but well-formed ISSUE request for testing.
func makeTokenIssueRequest(h2cObj crypto.H2CObject) (*BlindTokenRequest, [][]byte, []*crypto.Point, [][]byte, error) {
	tokens := make([][]byte, 1000)
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

var request, _, bP, _, _ = makeTokenIssueRequest(h2cObj)
var response, _ = ApproveTokens(*request, key, "1.1", G, H)

// Move function
func recomputeComposites(G, Y *crypto.Point, P, Q []*crypto.Point, hash stdcrypto.Hash, curve elliptic.Curve) (*crypto.Point, *crypto.Point, error) {
	compositeM, compositeZ, _, err := crypto.ComputeComposites(hash, curve, G, Y, P, Q)
	return compositeM, compositeZ, err
}

func BenchmarkAdvertiserCheckProof(b *testing.B) {
	xbP, _ := crypto.BatchUnmarshalPoints(h2cObj.Curve(), response.Sigs)
	dleq, _ := crypto.UnmarshalBatchProof(h2cObj.Curve(), response.Proof)
	dleq.G = G
	dleq.H = H
	dleq.M, dleq.Z, _ = recomputeComposites(G, H, bP, xbP, h2cObj.Hash(), h2cObj.Curve())
	dleq.Verify()
}
