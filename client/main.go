package main

import (
	"bytes"
	"encoding/json"	
	"fmt"
	"io/ioutil"
	"log"	
	"net/http"
	"net/url"

	"github.com/kev-liao/challenge-bypass-server"	
)

// TODO: Put into format.go
type BidResponse struct {
	Bid int
}

type WinResponse struct {
	Price int
	Markup string
	Tokens []*btd.PaidTokens	
}

type FwdWinResponse struct {
	Price int
	Tokens []*btd.PaidTokens	
}

func bidArgMax(array []int) int {
	max := 0
	for i := 1; i < len(array); i++ {
		if array[i] > array[max] {
			max = i
		}
	}
	return max
}

func main() {
	client := &http.Client{}	
	aucSize := 20
	urls := make([]string, aucSize)
	bids := make([]int, aucSize)
	
	// 1. Visit callback URLs
	for i := 0; i < aucSize; i++ {
		urls[i] = "http://localhost:8080"
		resource := "/bidrequest"
		u, _ := url.ParseRequestURI(urls[i])
		u.Path = resource
		urlStr := u.String()
		request, err := http.NewRequest("GET", urlStr, nil)
		response, error := client.Do(request)
		if error != nil {
			log.Fatal(err)
			return
		}
		defer response.Body.Close()

		if response.Status == "200 OK" {
			body, _ := ioutil.ReadAll(response.Body)
			bidResponse := &BidResponse{}
			err = json.Unmarshal(body, &bidResponse)
			if err != nil {
				log.Fatal(err)
				return
			}
			bids[i] = bidResponse.Bid
		}
	}

	// 2. Run local auction
	winner := bidArgMax(bids)
	price := bids[winner]
	fmt.Println("Winner:", winner)
	fmt.Println("Price:", price)
	
	// 3. Send winNotice
	winnerUrl := urls[winner]
	resource := "/win"
	u, _ := url.ParseRequestURI(winnerUrl)
	u.Path = resource
	urlStr := u.String()
	winningBid := &BidResponse{}
	winningBid.Bid = price
	jsonData, err := json.Marshal(winningBid)
	if err != nil {
		log.Fatal(err)
		return
	}
	request, err := http.NewRequest("POST", urlStr, bytes.NewBuffer(jsonData))
	response, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer response.Body.Close()	
	fmt.Println(response.Status)
	if response.Status == "200 OK" {
		fmt.Println(response.Header)
		body, _ := ioutil.ReadAll(response.Body)
		winResponse := &WinResponse{}		
		err = json.Unmarshal([]byte(body), &winResponse)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println(winResponse)

		// 4. Forward tokens		
		fwdWinResponse := &FwdWinResponse{}
		fwdWinResponse.Price = winResponse.Price
		fwdWinResponse.Tokens = winResponse.Tokens
		jsonData, err := json.Marshal(fwdWinResponse)
		if err != nil {
			log.Fatal(err)
			return
		}
		publisherUrl := "http://localhost:8081"
		resource = "/tokens"
		u, _ = url.ParseRequestURI(publisherUrl)
		u.Path = resource
		urlStr = u.String()
		fmt.Println(urlStr)
		request, err = http.NewRequest("POST", urlStr, bytes.NewBuffer(jsonData))
		if err != nil {
			log.Fatal(err)
			return
		}
		response, err = client.Do(request)
		if err != nil {
			log.Fatal(err)
			return
		}
		defer response.Body.Close()		
		fmt.Println(response.Status)
		if response.Status == "200 OK" {
			fmt.Println(response.Header)
			body, _ := ioutil.ReadAll(response.Body)
			fmt.Println(string(body))
		}
	}
}
