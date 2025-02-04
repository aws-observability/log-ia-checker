package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func main() {
	//Get region from os arg
	if len(os.Args) < 2 {
		log.Fatal("Error: Missing Region or Output File Argument Usage: log-ia-review region outfile")
	}
	region := os.Args[1]
	outfile := os.Args[2]

	//Built a log and trail client
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	log_client := cloudwatchlogs.NewFromConfig(cfg)
	cloudtrail_client := cloudtrail.NewFromConfig(cfg)

	//get list of log groups and perform some initial checks on the describe output
	log.Println("Retrieving list of log groups and performing initial checks.")
	logList := getLogList(log_client)

	//removeliveTailEvents TODO: do more stuff in cTrail
	log.Println("Checking for and removing logs with LiveTail events")
	logList = removeLiveTail(logList, cloudtrail_client)

	//remove export events TODO: try to make this more modular
	log.Println("Checking for and removing logs with export events")
	logList = removeExport(logList, cloudtrail_client)

	log.Printf("Logs that should be considered for transition to IA: %d \n", len(logList))
	log.Printf("Writing list to: %s", outfile)

	err = writeToFile(outfile, logList)
	if err != nil {
		log.Printf("error writing to outfile: %s", err)
	}
}
