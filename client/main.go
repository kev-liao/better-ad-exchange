package main

import (
	"bytes"
	"encoding/json"	
	"fmt"
	"io/ioutil"
	"log"	
	"net/http"
	"net/url"
	"time"

	"github.com/kev-liao/challenge-bypass-server"	
)

func makeURL(urlStr, resource string) string {
	u, _ := url.ParseRequestURI(urlStr)
	u.Path = resource
	return u.String()
}

func makeBidRequest(id int, callbackUrl string, ch chan<-btd.BidResponse) {
	client := &http.Client{}		
	request, err := http.NewRequest(
		"GET",
		makeURL(callbackUrl, "/bidrequest"),
		nil)
	if err != nil {
		log.Fatal(err)
		ch <- btd.BidResponse{Id: id, Bid: 0}
		return
	}	
	response, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
		ch <- btd.BidResponse{Id: id, Bid: 0}
		return
	}
	defer response.Body.Close()

	if response.Status == "200 OK" {
		body, _ := ioutil.ReadAll(response.Body)
		bidResponse := &btd.BidResponse{}
		err = json.Unmarshal(body, &bidResponse)
		if err != nil {
			log.Fatal(err)
			ch <- btd.BidResponse{Id: id, Bid: 0}			
			return
		}
		bidResponse.Id = id
		ch <- *bidResponse
		return
	} else {
		ch <- btd.BidResponse{Id: id, Bid: 0}
		return		
	}
}

func getMaxBid(bids []btd.BidResponse) btd.BidResponse {
	max := 0
	for i := 1; i < len(bids); i++ {
		if bids[i].Bid > bids[max].Bid {
			max = i
		}
	}
	return bids[max]
}

func main() {
	aucSize := 20
	urls := make([]string, aucSize)
	bids := make([]btd.BidResponse, aucSize)
	
	// 1. Visit callback URLs
	ch := make(chan btd.BidResponse)
	start := time.Now()
	for i := 0; i < aucSize; i++ {
		// TODO: Pre-initialize urls
		urls[i] = "http://localhost:8080"		
		go makeBidRequest(i, urls[i], ch)
	}
	for i := range bids {
		bids[i] = <-ch 
	}
    elapsed := time.Since(start)
    log.Printf("Visit callback URLs: %s", elapsed)

	// 2. Run local auction
	maxBid := getMaxBid(bids)
	winner := maxBid.Id
	price := maxBid.Bid
	fmt.Printf("Winner: %d\nPrice: %d\n", winner, price)
	
	// 3. Send winNotice
	winnerUrl := urls[winner]
	jsonBid, err := json.Marshal(maxBid)
	if err != nil {
		log.Fatal(err)
		return
	}
	request, err := http.NewRequest(
		"POST",
		makeURL(winnerUrl, "/win"),
		bytes.NewBuffer(jsonBid))
	if err != nil {
		log.Fatal(err)
		return
	}
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer response.Body.Close()	
	fmt.Printf("Win notice response: %s\n", response.Status)
	if response.Status == "200 OK" {
		fmt.Println(response.Header)
		body, _ := ioutil.ReadAll(response.Body)
		winResponse := &btd.WinResponse{}		
		err = json.Unmarshal([]byte(body), &winResponse)
		if err != nil {
			log.Fatal(err)
			return
		}
		fmt.Println(winResponse)
		
		// 4. Pay tokens
		tokenPayment := &btd.TokenPayment{
			Price: winResponse.Price,
			Tokens: winResponse.Tokens}
		jsonPayment, err := json.Marshal(tokenPayment)
		if err != nil {
			log.Fatal(err)
			return
		}
		publisherUrl := "http://localhost:8081"
		start = time.Now()		
		request, err = http.NewRequest(
			"POST",
			makeURL(publisherUrl, "/tokens"),
			bytes.NewBuffer(jsonPayment))
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
		fmt.Printf("Payment response: %s\n", response.Status)		
		if response.Status == "200 OK" {
			fmt.Println(response.Header)
			body, _ := ioutil.ReadAll(response.Body)
			fmt.Println(string(body))
		}
		elapsed = time.Since(start)
		log.Printf("Pay tokens: %s", elapsed)		
	}
}
