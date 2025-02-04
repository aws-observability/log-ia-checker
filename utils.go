// This file contains utility functions
package main

import (
	"bufio"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
)

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

func parseLogGroupArn(logGroupArn *string) string {
	// Assuming the log group ARN looks like: arn:aws:logs:region:account-id:log-group:log-group-name
	arnParts := strings.Split(aws.ToString(logGroupArn), ":log-group:")
	if len(arnParts) > 1 {
		return arnParts[1]
	}
	return ""
}

func writeToFile(fileName string, lines []string) error {
	// Open the file for writing (create if it doesn't exist)
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	// Create a buffered writer
	writer := bufio.NewWriter(file)

	// Write each line to the file
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}

	// Flush the buffered writer to ensure all data is written
	err = writer.Flush()
	if err != nil {
		return err
	}

	return nil
}
