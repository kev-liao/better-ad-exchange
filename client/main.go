package main

import (
	//"bytes"
	"encoding/json"	
	"fmt"
	"io/ioutil"
	"log"	
	"net/http"
	"net/url"
	"strconv"
	"strings"

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
	urls = 
	// 1. Visit callbackURLs
	// 2. Run local auction
	// 3. Send winNotice	

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
		fwdWinResponse := &FwdWinResponse{}
		fwdWinResponse.Price = winResponse.Price
		fwdWinResponse.Tokens = winResponse.Tokens
		jsonData, err := json.Marshal(fwdWinResponse)
		if err != nil {
			log.Fatal(err)
			return
		}

		// 4. Forward tokens
		publisherUrl := "http://localhost:8081"
		resource = "/tokens"
		u, _ = url.ParseRequestURI(publisherUrl)
		u.Path = resource
		urlStr = u.String()
		fmt.Println(urlStr)
		request, err = http.NewRequest("POST", urlStr, bytes.NewBuffer(jsonData))
		request.Header().Set("Content-Type", "application/json")
		//request.Header.Set("Content-Type", "application/x-www-form-urlencoded; param=value")
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
	response.Body.Close()	
}
