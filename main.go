package main

import (
	"context"
	"flag"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
)

func main() {
	// Define flags
	outfilePtr := flag.String("outfile", "ia.txt", "Output file path (default: ia.txt)")
	
	// Custom usage message
	flag.Usage = func() {
		log.Printf("Usage: %s [OPTIONS] [REGION]\n", os.Args[0])
		log.Println("  REGION: AWS region (optional if AWS_REGION environment variable is set)")
		log.Println("Options:")
		flag.PrintDefaults()
	}
	
	// Parse flags
	flag.Parse()
	
	// Get region from remaining args or environment variable
	var region string
	if flag.NArg() > 0 {
		region = flag.Arg(0)
	} else {
		region = os.Getenv("AWS_REGION")
		if region == "" {
			log.Fatal("Error: No region provided and AWS_REGION environment variable not set")
		}
	}
	
	// Use the outfile from flag
	outfile := *outfilePtr

	// Build a log and trail client
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	log_client := cloudwatchlogs.NewFromConfig(cfg)
	cloudtrail_client := cloudtrail.NewFromConfig(cfg)

	// Retrieve list of log groups and perform initial checks
	log.Println("Retrieving list of log groups and performing initial checks.")
	logList := getLogList(log_client)

	// Progress bar for log group retrieval
	totalLogs := len(logList)
	for i := 0; i < totalLogs; i++ {
		time.Sleep(50 * time.Millisecond) // Simulate processing delay
		progressBar(i+1, totalLogs, "Retrieving and checking log groups")
	}

	// Remove liveTail events
	log.Println("Checking for and removing logs with LiveTail events")
	logList = removeLiveTail(logList, cloudtrail_client)

	// Progress bar for liveTail event removal
	totalLogs = len(logList)
	for i := 0; i < totalLogs; i++ {
		time.Sleep(50 * time.Millisecond) // Simulate processing delay
		progressBar(i+1, totalLogs, "Removing LiveTail events")
	}

	// Remove export events
	log.Println("Checking for and removing logs with export events")
	logList = removeExport(logList, cloudtrail_client)

	// Progress bar for export event removal
	totalLogs = len(logList)
	for i := 0; i < totalLogs; i++ {
		time.Sleep(50 * time.Millisecond) // Simulate processing delay
		progressBar(i+1, totalLogs, "Removing export events")
	}

	// Output the final count of logs
	log.Printf("Logs that should be considered for transition to IA: %d \n", len(logList))
	log.Printf("Writing list to: %s", outfile)

	// Write the log list to the output file
	err = writeToFile(outfile, logList)
	if err != nil {
		log.Printf("error writing to outfile: %s", err)
	}
}
