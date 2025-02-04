package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func main() {
	//Built a log client
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	log_client := cloudwatchlogs.NewFromConfig(cfg)
	cloudtrail_client := cloudtrail.NewFromConfig(cfg)

	//get list of log groups
	logList := getLogList(log_client)

	//removeliveTailEvents TODO: do more stuff in cTrail
	logList = removeLiveTail(logList, cloudtrail_client)

	//remove export events TODO: try to make this more modular
	logList = removeExport(logList, cloudtrail_client)

	fmt.Println("Length of Log group list who can be IA:")
	fmt.Println(len(logList))
}
