package main

import (
	"encoding/json"
	"flag"	
	"fmt"
	"io/ioutil"	
	"log"
	//"math/rand"	
	"net/http"

	"github.com/kev-liao/challenge-bypass-server"
)

type AdServer struct {
	PaidTokens map[int]*btd.PaidTokens
}

func (s *AdServer) bidRequestHandler(w http.ResponseWriter, r *http.Request) {
    if r.URL.Path != "/bidrequest" {
        http.Error(w, "404 not found.", http.StatusNotFound)
        return
    }

    if r.Method != "GET" {
        http.Error(w, "Method is not supported.", http.StatusNotFound)
        return
    }

	//min := 235
    //max := 255
    //bid := rand.Intn(max - min) + min
	bid := 255

	response := &btd.BidResponse{Bid: bid}
	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Fatal(err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonData)
	
	return
}

func (s *AdServer) winNoticeHandler(w http.ResponseWriter, r *http.Request) {
	bidRequest := &btd.BidResponse{}
	err := json.NewDecoder(r.Body).Decode(&bidRequest)	
	if err != nil {
		log.Fatal(err)
		return
    }	
	href := "https://adidas.com"
	src := "https://picsum.photos/seed/picsum/200/300"
	price := bidRequest.Bid
	markup :=  fmt.Sprintf("<a href=\"%s\"><img src=\"%s\"></a>", href, src)
	
	response := &btd.WinResponse{Price: price, Markup: markup, Tokens: []*btd.PaidTokens{}}
	for i := 0; i < 8; i++ {
		if (price >> i & 1) == 1 {
			response.Tokens = append(response.Tokens, s.PaidTokens[i])
		}
	}

	jsonData, err := json.Marshal(response)
	if err != nil {
		log.Fatal(err)
		return
	}
	
	w.Header().Set("Content-Type", "application/json")	
	w.Write(jsonData)
	
	return
}

func main() {
	var address, tokenFile string
	var port int

	flag.StringVar(&address, "addr", "127.0.0.1", "address to send to")
	flag.IntVar(&port, "p", 2416, "port to send on")
	flag.StringVar(&tokenFile, "in", "", "path to the token file")
	flag.Parse()

	srv := &AdServer{}
	srv.PaidTokens = make(map[int]*btd.PaidTokens)

	file, err := ioutil.ReadFile(tokenFile)
	if err != nil {
		log.Fatal(err)
		return
	}
		
	err = json.Unmarshal([]byte(file), &srv.PaidTokens)
	if err != nil {
		log.Fatal(err)
		return
	}
	
    http.HandleFunc("/bidrequest", srv.bidRequestHandler)
	http.HandleFunc("/win", srv.winNoticeHandler)
	
    fmt.Printf("Starting ad server at port 8080\n")
    if err := http.ListenAndServe(":8080", nil); err != nil {
        log.Fatal(err)
    }	
}
