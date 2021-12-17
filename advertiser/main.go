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

var errLog *log.Logger = log.New(os.Stderr, "[advertiser] ", log.LstdFlags|log.Lshortfile)

type Config struct {
	BindAddress        string `json:"bind_address,omitempty"`
	ListenPort         int    `json:"listen_port,omitempty"`
	MetricsPort        int    `json:"metrics_port,omitempty"`
	MaxTokens          int    `json:"max_tokens,omitempty"`
	SignKeyFilePath    string `json:"key_file_path"`
	RedeemKeysFilePath string `json:"redeem_keys_file_path"`	
	CommFilePath       string `json:"comm_file_path"`

	signKey    []byte        // a big-endian marshaled big.Int representing an elliptic curve scalar for the current signing key
	redeemKeys [][]byte      // current signing key + all old keys
	G          *crypto.Point // elliptic curve point representation of generator G
	H          *crypto.Point // elliptic curve point representation of commitment H to signing key
	keyVersion string        // the version of the key that is used
}

var DefaultConfig = &Config{
	BindAddress: "127.0.0.1",
	ListenPort:  2416,
	MetricsPort: 2417,
	MaxTokens:   100,
}

func wrapTokenRequest(req *btd.BlindTokenRequest) *btd.BlindTokenRequestWrapper {
	encoded, _ := btd.MarshalRequest(req)
	wrappedRequest := &btd.BlindTokenRequestWrapper{
		Request: encoded,
	}
	return wrappedRequest
}

func (c *Config) loadKeys() error {
	//if c.SignKeyFilePath == "" {
	//	return ErrEmptyKeyPath
	//} else if c.CommFilePath == "" {
	//	return ErrEmptyCommPath
	//}

	// Parse current signing key
	_, currkey, err := crypto.ParseKeyFile(c.SignKeyFilePath, true)
	if err != nil {
		return err
	}
	c.signKey = currkey[0]
	c.redeemKeys = append(c.redeemKeys, c.signKey)

	// optionally parse old keys that are valid for redemption
	if c.RedeemKeysFilePath != "" {
		errLog.Println("Adding extra keys for verifying token redemptions")
		_, oldKeys, err := crypto.ParseKeyFile(c.RedeemKeysFilePath, false)
		if err != nil {
			return err
		}
		c.redeemKeys = append(c.redeemKeys, oldKeys...)
	}

	return nil
}

func main() {
	var err error
	cnf := *DefaultConfig

	flag.StringVar(&cnf.BindAddress, "addr", "127.0.0.1", "address to listen on")
	flag.IntVar(&cnf.ListenPort, "p", 2416, "port to listen on")
	flag.IntVar(&cnf.MetricsPort, "m", 2417, "metrics port")	
	flag.IntVar(&cnf.MaxTokens, "maxtokens", 100, "maximum number of tokens issued per request")
	flag.StringVar(&cnf.SignKeyFilePath, "key", "", "path to the current secret key file for signing tokens")
	flag.StringVar(&cnf.CommFilePath, "comm", "", "path to the commitment file")
	flag.StringVar(&cnf.keyVersion, "keyversion", "1.0", "version sent to the client for choosing consistent key commitments for proof verification")
	flag.Parse()
	
	if cnf.SignKeyFilePath == "" || cnf.CommFilePath == "" {
		flag.Usage()
		return
	}

	err = cnf.loadKeys()
	if err != nil {
		errLog.Fatal(err)
		return
	}

	// Get bytes for public commitment to private key
	GBytes, HBytes, err := crypto.ParseCommitmentFile(cnf.CommFilePath)
	if err != nil {
		errLog.Fatal(err)
		return
	}
	
	// Retrieve the actual elliptic curve points for the commitment
	// The commitment should match the current key that is being used for
	// signing
	//
	// We only support curve point commitments for P256-SHA256
	cnf.G, cnf.H, err = crypto.RetrieveCommPoints(GBytes, HBytes, cnf.signKey)
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
	
	tokens := make([][]byte, 10)
	bF := make([][]byte, len(tokens))
	bP := make([]*crypto.Point, len(tokens))
	for i := 0; i < len(tokens); i++ {
		token, bPoint, bFactor, err := crypto.CreateBlindToken(h2cObj)
		if err != nil {
			errLog.Fatal(err)			
			return
		}
		tokens[i] = token
		bP[i] = bPoint
		bF[i] = bFactor
	}
	marshaledTokenList, err := crypto.BatchMarshalPoints(bP)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	request := &btd.BlindTokenRequest{
		Type:     "Issue",
		Contents: marshaledTokenList,
	}

	wrapped := wrapTokenRequest(request)
	jsonReq, err := json.Marshal(wrapped)
	if err != nil {
		errLog.Fatal(err)
		return
	}	
	
	CONNECT := fmt.Sprintf("%s:%s", cnf.BindAddress, strconv.Itoa(cnf.ListenPort))
	
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		errLog.Fatal(err)
		return
	}

	_, err = c.Write(jsonReq)

	reply, err := ioutil.ReadAll(c)
	
    if err != nil {
		errLog.Fatal(err)
		return		
    }
	
	fmt.Println(string(reply))
	
	return
}
