// This file will containt the functions utilized for making cloudwatchlogs client calls.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatchLogsClient is an interface for CloudWatch Logs operations
type CloudWatchLogsClient interface {
	DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	DescribeFieldIndexes(ctx context.Context, params *cloudwatchlogs.DescribeFieldIndexesInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeFieldIndexesOutput, error)
	DescribeSubscriptionFilters(ctx context.Context, params *cloudwatchlogs.DescribeSubscriptionFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeSubscriptionFiltersOutput, error)
	ListLogAnomalyDetectors(ctx context.Context, params *cloudwatchlogs.ListLogAnomalyDetectorsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListLogAnomalyDetectorsOutput, error)
}

// Return a list of logs who can be IA because they are not utilizing any standard features.
func getLogList(client CloudWatchLogsClient) []string {
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
			if !checkLogGroup(value) {
				logList = append(logList, *value.LogGroupArn)
			}
		}
		pageNum++
	}

	log.Println("Checking for logs with index policies")
	logList = getAllIndexPolicies(logList, client)
	logList = parseLogGroupArns(logList)

	log.Println("Checking for logs with subscription filters")
	filteredList := getFilteredLogListConcurrently(logList, client)

	log.Println("Checking for logs with anomaly detectors")
	filteredList = findAllLogAnomalyDetectors(filteredList, client)

	return filteredList
}

// Describe Log Group Checks
func checkLogGroup(logGroup types.LogGroup) bool {
	conditions := []func(logGroup types.LogGroup) bool{
		hasMetricFilter,
		hasDataProtectionPolicy,
		isIA,
		hasInsights,
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

// check for metric filters
func hasMetricFilter(logGroup types.LogGroup) bool {
	return aws.ToInt32(logGroup.MetricFilterCount) > 0
}

// check for data protection policy
func hasDataProtectionPolicy(logGroup types.LogGroup) bool {
	if logGroup.DataProtectionStatus == types.DataProtectionStatusActivated {
		return true
	}
	return false
}

// check if insights
func hasInsights(logGroup types.LogGroup) bool {
	logGroupName := aws.ToString(logGroup.LogGroupName) // Convert to string
	// Check if the log group name contains "lambda-insights" or "containerinsights"
	return strings.Contains(logGroupName, "lambda-insights") || strings.Contains(logGroupName, "containerinsights")
}

// Index Policy Checks
func getAllIndexPolicies(logList []string, client CloudWatchLogsClient) []string {
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

func fetchIndexPoliciesForBatch(batch []string, client CloudWatchLogsClient) []string {
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
func getFilteredLogListConcurrently(logList []string, client CloudWatchLogsClient) []string {
	var filteredList []string
	var mu sync.Mutex     // To safely append to the shared slice
	var wg sync.WaitGroup // To wait for all goroutines to complete
	concurrency := 2      // Number of concurrent requests (adjust as needed)

	// Create a semaphore to limit concurrent requests
	sem := make(chan struct{}, concurrency)

	totalLogs := len(logList)

	// Track progress
	for i, logGroupName := range logList {
		wg.Add(1)
		sem <- struct{}{} // Acquire a semaphore slot

		go func(logGroupName string, index int) {
			defer wg.Done()
			defer func() { <-sem }() // Release the semaphore slot

			// Delay for backoff
			time.Sleep(200 * time.Millisecond)

			// Here you would make the actual DescribeSubscriptionFilters API call
			// Example:
			resp, err := client.DescribeSubscriptionFilters(context.TODO(), &cloudwatchlogs.DescribeSubscriptionFiltersInput{
				LogGroupName: &logGroupName,
			})
			if err != nil {
				fmt.Printf("Error describing subscription filters for %s: %v\n", logGroupName, err)
				return
			}

			// If no subscription filters are found, add to filtered list
			if len(resp.SubscriptionFilters) == 0 {
				mu.Lock()
				filteredList = append(filteredList, logGroupName)
				mu.Unlock()
			}

			// Update progress bar after each log group is processed
			progressBar(index+1, totalLogs, "Finding Subscription Filters")
		}(logGroupName, i)
	}

	// Wait for all goroutines to finish
	wg.Wait()

	return filteredList
}

func findAllLogAnomalyDetectors(logList []string, client CloudWatchLogsClient) []string {
	var nextToken *string
	var filteredList []string

	// Create a map to store log groups with anomaly detectors for faster lookups
	anomalyLogGroups := make(map[string]bool)

	for {
		// Make the ListLogAnomalyDetectors API call
		input := &cloudwatchlogs.ListLogAnomalyDetectorsInput{
			NextToken: nextToken, // For pagination
		}

		resp, err := client.ListLogAnomalyDetectors(context.TODO(), input)
		if err != nil {
			log.Fatalf("Failed to list anomaly detectors: %v", err)
		}

		// Process the results and add log group names to the anomalyLogGroups map
		for _, detector := range resp.AnomalyDetectors {
			// Loop through the list of log group ARNs that the detector watches
			for _, logGroupArn := range detector.LogGroupArnList {
				logGroupName := parseLogGroupArn(aws.String(logGroupArn))
				anomalyLogGroups[logGroupName] = true
			}
		}

		// Check if there's a NextToken for pagination
		if resp.NextToken == nil {
			break // No more pages, so exit the loop
		}

		// Set the nextToken for the next request
		nextToken = resp.NextToken
	}

	for _, logGroup := range logList {
		if !anomalyLogGroups[logGroup] {
			filteredList = append(filteredList, logGroup)
		}
	}

	log.Printf("Logs Still in consideration: %d", len(filteredList))
	return filteredList
}
