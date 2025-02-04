package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func main() {
	//Get region from os arg
	if len(os.Args) < 2 {
		log.Fatal("Error: Missing Region Argument")
	}
	region := os.Args[1]

	//Built a log and trail client
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	log_client := cloudwatchlogs.NewFromConfig(cfg)
	cloudtrail_client := cloudtrail.NewFromConfig(cfg)

	//get list of log groups and perform some initial checks on the describe output
	logList := getLogList(log_client)

	//removeliveTailEvents TODO: do more stuff in cTrail
	logList = removeLiveTail(logList, cloudtrail_client)

	//remove export events TODO: try to make this more modular
	logList = removeExport(logList, cloudtrail_client)

	fmt.Println("Length of Log group list who can be IA:")
	fmt.Println(len(logList))
}
