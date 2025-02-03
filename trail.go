// This file is for making CloudTrail calls. Some of the features that are standard only are API calls such as Live Tail
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// Remove log groups that have had a LiveTail call against them.
func removeLiveTail(logList []string, client *cloudtrail.Client) []string {
	endTime := time.Now()
	startTime := time.Now().AddDate(0, 0, -30)
	fmt.Println("Checking log groups for recent LiveTail activities")

	// Call CloudTrail to get recent LiveTail events
	resp, err := client.LookupEvents(context.TODO(), &cloudtrail.LookupEventsInput{
		EndTime:   &endTime,
		StartTime: &startTime,
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventName,
				AttributeValue: aws.String("StartLiveTail"),
			},
		},
	})
	if err != nil {
		log.Printf("Error finding trail events: %v", err)
		return logList // Return the original list in case of error
	}

	// List to store log groups where LiveTail events occurred
	var liveTailList []string

	fmt.Printf("Found %d LiveTail Events \n", len(resp.Events))

	// Loop through CloudTrail events and extract log group identifiers
	for _, event := range resp.Events {
		// Assuming CloudTrailEvent is a JSON string, we need to parse it
		var eventDetails map[string]interface{}
		err := json.Unmarshal([]byte(*event.CloudTrailEvent), &eventDetails)
		if err != nil {
			log.Printf("Error parsing CloudTrail event: %v", err)
			continue
		}

		// Extract the log group identifiers from the event's requestParameters
		if requestParams, ok := eventDetails["requestParameters"].(map[string]interface{}); ok {
			if logGroups, ok := requestParams["logGroupIdentifiers"].([]interface{}); ok {
				for _, lg := range logGroups {
					if logGroupArn, ok := lg.(string); ok {
						liveTailList = append(liveTailList, logGroupArn)
						fmt.Printf("Appending %s to liveTail List \n", logGroupArn)
					}
				}
			}
		}
	}

	//change arn to log group name in livetail logList
	liveTailList = parseLogGroupArns(liveTailList)

	// Create a filtered list of log groups that have NOT had a LiveTail event
	var filteredLogList []string
	liveTailMap := make(map[string]bool)
	for _, lg := range liveTailList {
		liveTailMap[lg] = true
	}

	// Filter out log groups that have had a LiveTail event
	for _, logGroup := range logList {
		if !liveTailMap[logGroup] {
			filteredLogList = append(filteredLogList, logGroup)
		}
	}

	return filteredLogList
}
