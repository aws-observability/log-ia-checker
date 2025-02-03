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

	// Create a paginator for LookupEvents
	paginator := cloudtrail.NewLookupEventsPaginator(client, &cloudtrail.LookupEventsInput{
		EndTime:   &endTime,
		StartTime: &startTime,
		LookupAttributes: []types.LookupAttribute{
			{
				AttributeKey:   types.LookupAttributeKeyEventName,
				AttributeValue: aws.String("StartLiveTail"),
			},
		},
	})

	// List to store log groups where LiveTail events occurred
	var liveTailList []string

	// Iterate through pages of events
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("Error retrieving CloudTrail events: %v", err)
			return logList // Return the original list in case of error
		}

		// Process each event in the page
		for _, event := range page.Events {
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
	}

	liveTailList = parseLogGroupArns(liveTailList)

	// Create a filtered list of log groups that have NOT had a LiveTail event
	var filteredLogList []string
	liveTailMap := make(map[string]bool)
	for _, lg := range liveTailList {
		liveTailMap[lg] = true
	}

	for _, logGroup := range logList {
		if !liveTailMap[logGroup] {
			filteredLogList = append(filteredLogList, logGroup)
		}
	}

	return filteredLogList
}
