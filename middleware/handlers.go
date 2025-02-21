package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"io"
	"io/ioutil"
	pers "kai_hiringtest/persistance"
	"kai_hiringtest/types"
	"log"
	"time"

	//"log"
	"net/http"
	"sync"
)

func Inithandlers(ctx context.Context) {
	r := mux.NewRouter()
	//context.WithDeadline(ctx, time.Time{})
	//ctx.Value(`TraceId`)

	r.HandleFunc("/scan", scanhandler)
	r.HandleFunc("/query", queryhandler)

	err := http.ListenAndServe(":8080", r)
	if err != nil {
		return
	}

}

var scanhandler = func(writer http.ResponseWriter, request *http.Request) {
	// dosomething

	payload := getfilefromreq(request.Body)
	defer request.Body.Close()

	files := payload.Files
	wg := sync.WaitGroup{}
	type details struct {
		status  bool
		fileidx int
	}

	donecount := 0
	donearr := make([]bool, len(files))

	const maxretries = 2
	for retry := 0; retry < maxretries; retry++ {
		done := make(chan details, len(files))

		if donecount == len(files) {
			break
		}

		for lidx, lFile := range files {
			if donearr[lidx] == true {
				continue
			}
			wg.Add(1)
			go func(lFile string, lidx int) {
				defer wg.Done()

				// do reverse proxy with timeout
				response := sendreverseproxy(lFile, payload.Repo)

				if response.StatusCode != http.StatusOK {
					done <- details{false, lidx}
					return
				}

				//response := &http.Response{}
				defer response.Body.Close()

				lbody, err := ioutil.ReadAll(response.Body)
				if err != nil {
					log.Println(err)
					return
				}

				var scanresults []types.ScanResultWrapper
				err = json.Unmarshal(lbody, &scanresults)
				if err != nil {
					log.Println(err)
					done <- details{false, lidx}
					return
				}
				err = pers.Insertintodb(scanresults)
				if err != nil {
					log.Println(err)
					done <- details{false, lidx}
				} else {
					done <- details{true, lidx}
				}

			}(lFile, lidx)

		}

		go func() {
			wg.Wait()
			close(done)
		}()

		for i := range done {
			fmt.Printf("Scanned file number #%d\n", i)
			donearr[i.fileidx] = i.status
			if i.status {
				donecount++
			}
		}
	}

	if donecount < len(files) {
		writer.WriteHeader(http.StatusInternalServerError)
	}

	writer.WriteHeader(http.StatusOK)

}

var client = http.Client{Timeout: time.Second * 10}

func sendreverseproxy(file string, repo string) *http.Response {

	//https://raw.githubusercontent.com/velancio/vulnerability_scans/refs/heads/main/vulnscan1011.json

	urlquery := fmt.Sprintf("https://raw.githubusercontent.com/" + repo + "/vulnerability_scans/refs/heads/main/" + file)
	log.Println("Sending reverse proxy to " + urlquery)

	request, err := http.NewRequest("GET", urlquery, nil)
	if err != nil {
		return nil
	}

	//client := &http.Client{}

	resp, err := client.Do(request)
	if err != nil {
		return nil
	}

	return resp
}

type RequestPayload struct {
	Repo  string   `json:"repo"`
	Files []string `json:"files"`
}

func getfilefromreq(body io.ReadCloser) RequestPayload {

	var payload RequestPayload

	err := json.NewDecoder(body).Decode(&payload)
	if err != nil {
		fmt.Println("here error in decoding", err.Error())

		return RequestPayload{}
	}
	fmt.Println("here")

	return payload
}

var queryhandler = func(writer http.ResponseWriter, request *http.Request) {

	results := []types.Vulnerability{}

	type Filter struct {
		Severity string `json:"severity"`
	}
	type requestpayload struct {
		Filter Filter `json:"filters"`
	}

	var lpayload requestpayload
	err := json.NewDecoder(request.Body).Decode(&lpayload)
	fmt.Println("here", err)
	// todo query with pagination
	results = pers.QueryfromDB(lpayload.Filter.Severity)

	writer.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(writer).Encode(results); err != nil {
		http.Error(writer, "Error encoding JSON", http.StatusInternalServerError)
		log.Println("JSON encoding error:", err)
	}
	return
}
