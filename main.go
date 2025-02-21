package main

import (
	"context"
	"kai_hiringtest/middleware"
	pers "kai_hiringtest/persistance"
	"log"
)

func main() {

	ctx := context.Background()

	log.Println("initializing application")
	//initializes sqlite tables
	pers.InitDB()
	//registers handlers for scan and query and starts server
	middleware.Inithandlers(ctx)

}
