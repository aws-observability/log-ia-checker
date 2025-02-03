package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
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

	fmt.Println("Length of Log group list who can be IA:")
	fmt.Println(len(logList))
}

// Return a list of logs who can be IA because they are not utilizing any standard features.
func getLogList(client *cloudwatchlogs.Client) []string {
	//Create empty list to store log group names
	var logList []string

	//Create paginator so i can get all the log groups
	describeLogsPaginator := cloudwatchlogs.NewDescribeLogGroupsPaginator(client, &cloudwatchlogs.DescribeLogGroupsInput{})

	pageNum := 0
	for describeLogsPaginator.HasMorePages() {
		output, err := describeLogsPaginator.NextPage(context.TODO())
		if err != nil {
			log.Printf("error: %v", err)
		}
		for _, value := range output.LogGroups {
			fmt.Printf("Checking log group: %s \n", *value.LogGroupArn)
			if !checkLogGroup(value) {
				logList = append(logList, *value.LogGroupArn)
			}
		}
		pageNum++
	}

	logList = getAllIndexPolicies(logList, client)
	logList = parseLogGroupArns(logList)

	filteredList := getFilteredLogListConcurrently(logList, client)

	return filteredList
}

// Describe Log Group Checks
func checkLogGroup(logGroup types.LogGroup) bool {
	conditions := []func(logGroup types.LogGroup) bool{
		hasMetricFilter,
		hasDataProtectionPolicy,
		isIA,
		// Add more conditions here as needed
	}

	// Track if any condition returns true
	anyConditionTrue := false

	// Check all conditions
	for _, condition := range conditions {
		if condition(logGroup) {
			anyConditionTrue = true
		}
	}

	return anyConditionTrue // Return true if any condition was true
}

// Check if already IA
func isIA(logGroup types.LogGroup) bool {
	if logGroup.LogGroupClass == types.LogGroupClassInfrequentAccess {
		return true
	}
	return false
}

func hasMetricFilter(logGroup types.LogGroup) bool {
	return aws.ToInt32(logGroup.MetricFilterCount) > 0
}

func hasDataProtectionPolicy(logGroup types.LogGroup) bool {
	if logGroup.DataProtectionStatus == types.DataProtectionStatusActivated {
		return true
	}
	return false
}

// Index Policy Checks
func getAllIndexPolicies(logList []string, client *cloudwatchlogs.Client) []string {
	const batchSize = 100
	var filteredLogList []string

	// Split the logList into chunks of batchSize
	for i := 0; i < len(logList); i += batchSize {
		end := i + batchSize
		if end > len(logList) {
			end = len(logList)
		}
		batch := logList[i:end]

		// Call DescribeFieldIndexes and remove log groups that have index policies
		remainingBatch := fetchIndexPoliciesForBatch(batch, client)
		filteredLogList = append(filteredLogList, remainingBatch...)
	}

	return filteredLogList
}

func fetchIndexPoliciesForBatch(batch []string, client *cloudwatchlogs.Client) []string {
	var nextToken *string
	var remainingLogGroups []string

	for {
		// Call DescribeFieldIndexes with the current batch of log groups
		resp, err := client.DescribeFieldIndexes(context.TODO(), &cloudwatchlogs.DescribeFieldIndexesInput{
			LogGroupIdentifiers: batch,
			NextToken:           nextToken, // Set the next token from the previous page
		})
		if err != nil {
			log.Printf("Error describing index policies: %v", err)
			return batch // Return the entire batch if there's an error
		}

		// Create a map of log groups with index policies
		hasPolicy := make(map[string]bool)
		for _, policy := range resp.FieldIndexes {
			fmt.Printf("Found index policy on log: %s\n", *policy.LogGroupIdentifier)
			hasPolicy[*policy.LogGroupIdentifier] = true
		}

		// Keep log groups that don't have an index policy
		for _, logGroup := range batch {
			if !hasPolicy[logGroup] {
				remainingLogGroups = append(remainingLogGroups, logGroup)
			}
		}

		// If NextToken is nil, we've retrieved all pages
		if resp.NextToken == nil {
			break
		}

		// Update the nextToken for the next request
		nextToken = resp.NextToken
	}

	return remainingLogGroups
}

// Subscription filter check
func getFilteredLogListConcurrently(logList []string, client *cloudwatchlogs.Client) []string {
	var filteredList []string
	var mu sync.Mutex               // To safely append to the shared slice
	var wg sync.WaitGroup           // To wait for all goroutines to complete
	concurrency := 3                // Number of concurrent requests (adjust as needed)
	delay := 500 * time.Millisecond // Delay between requests (tunable)

	sem := make(chan struct{}, concurrency) // Semaphore to limit concurrent requests

	for _, logGroupName := range logList {
		wg.Add(1)
		sem <- struct{}{} // Acquire a semaphore slot

		go func(logGroupName string) {
			defer wg.Done()
			defer func() { <-sem }() // Release the semaphore slot
			defer time.Sleep(delay)  // Add delay to slow down the API calls

			fmt.Printf("Checking log group for subscription filters: %s \n", logGroupName)
			resp, err := client.DescribeSubscriptionFilters(context.TODO(), &cloudwatchlogs.DescribeSubscriptionFiltersInput{
				LogGroupName: aws.String(logGroupName),
			})
			if err != nil {
				log.Printf("Error describing subscription filters for %s: %v", logGroupName, err)
				return
			}

			// If no subscription filters are found, add to filtered list
			if len(resp.SubscriptionFilters) == 0 {
				mu.Lock() // Lock the mutex before modifying the shared slice
				filteredList = append(filteredList, logGroupName)
				mu.Unlock() // Unlock the mutex
			}
		}(logGroupName)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	return filteredList
}

//Helper Functions

// Change log group arns in list to just log group. This is necessary because some checks return arn and some return names.
// We will have the final output just be names because deriving the arn from name would require a second call to describe log group.
// Potentially we could do it by extracting the region and account id from other variables.
func parseLogGroupArns(logArns []string) []string {
	var logGroupNames []string

	for _, arn := range logArns {
		// Split by colon and get the last part after "log-group:"
		parts := strings.Split(arn, ":log-group:")
		if len(parts) > 1 {
			logGroupNames = append(logGroupNames, parts[1])
		}
	}

	return logGroupNames
}
