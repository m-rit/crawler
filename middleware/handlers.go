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
	registerhandlers(r)

	err := http.ListenAndServe(":8080", r)
	if err != nil {
		return
	}

}

func registerhandlers(r *mux.Router) {
	r.HandleFunc("/scan", scanhandler)
	r.HandleFunc("/query", queryhandler)
}

// scanhanldler parses the scan request  to get repo and filenames. Then it concurrently starts routines to fetch each file data. If all files are not fetched until max retries. it returns 500.
var scanhandler = func(writer http.ResponseWriter, request *http.Request) {

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

	const maxretries = 2 //maxretries is the number of times the server tries to fetch the files until it does not succeed.

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

				response := sendreverseproxy(lFile, payload.Repo)

				if response.StatusCode != http.StatusOK {
					done <- details{false, lidx}
					return
				}

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
			//fmt.Printf("Scanned file number #%d\n", i)
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

// HttpClient interface implements Do method that is used by both Http.Client and MockClient structs
type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// client that sends reverseproxy request
var client HttpClient = &http.Client{Timeout: time.Second * 10}

// sendreverseproxy sends request to github.com to fetch json files for a particular filename
func sendreverseproxy(file string, repo string) *http.Response {
	//https://raw.githubusercontent.com/velancio/vulnerability_scans/refs/heads/main/vulnscan1011.json
	owner := "velancio" // since requests do not have owner in body
	urlquery := fmt.Sprintf("https://raw.githubusercontent.com/" + owner + "/" + repo + "/refs/heads/main/" + file)
	log.Println("Sending reverse proxy to " + urlquery)

	request, err := http.NewRequest("GET", urlquery, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(request)
	if err != nil {
		return nil
	}

	return resp
}

// getfilefromreq parses the scan requests body to extract repo and file names
func getfilefromreq(body io.ReadCloser) types.RequestPayload {

	var payload types.RequestPayload

	err := json.NewDecoder(body).Decode(&payload)
	if err != nil {
		log.Println("here error in decoding", err.Error())

		return types.RequestPayload{}
	}

	return payload
}

// queryhandler implements the handler for query request. It parses the request body to get severity value and returns all matching rows in response
var queryhandler = func(writer http.ResponseWriter, request *http.Request) {

	results := []types.Vulnerability{}

	var lpayload types.Querypayload
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
