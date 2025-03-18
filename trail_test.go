package main

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

// CloudTrailAPI defines the interface for CloudTrail client operations
type CloudTrailAPI interface {
	LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error)
}

// Mock CloudTrail client for testing
type mockCloudTrailClient struct {
	CloudTrailAPI
	lookupEventsOutput *cloudtrail.LookupEventsOutput
	lookupEventsErr    error
}

func (m *mockCloudTrailClient) LookupEvents(ctx context.Context, params *cloudtrail.LookupEventsInput, optFns ...func(*cloudtrail.Options)) (*cloudtrail.LookupEventsOutput, error) {
	return m.lookupEventsOutput, m.lookupEventsErr
}

func TestRemoveLiveTail(t *testing.T) {
	// Create a CloudTrail event with LiveTail information
	liveTailEvent := createMockCloudTrailEvent("StartLiveTail", map[string]interface{}{
		"logGroupIdentifiers": []interface{}{
			"arn:aws:logs:us-west-2:123456789012:log-group:log1",
		},
	})

	tests := []struct {
		name           string
		logList        []string
		mockResponse   *cloudtrail.LookupEventsOutput
		mockError      error
		expectedResult []string
	}{
		{
			name:    "No LiveTail events found",
			logList: []string{"log1", "log2", "log3"},
			mockResponse: &cloudtrail.LookupEventsOutput{
				Events: []types.Event{},
			},
			mockError:      nil,
			expectedResult: []string{"log1", "log2", "log3"},
		},
		{
			name:    "LiveTail events found for some logs",
			logList: []string{"log1", "log2", "log3"},
			mockResponse: &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						CloudTrailEvent: aws.String(liveTailEvent),
					},
				},
			},
			mockError:      nil,
			expectedResult: []string{"log2", "log3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mockClient := &mockCloudTrailClient{
				lookupEventsOutput: tt.mockResponse,
				lookupEventsErr:    tt.mockError,
			}

			result := removeLiveTail(tt.logList, mockClient)
			
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("removeLiveTail() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

func TestRemoveExport(t *testing.T) {
	// Create a CloudTrail event with export information
	exportEvent := createMockCloudTrailEvent("CreateExportTask", map[string]interface{}{
		"logGroupName": "log1",
	})

	tests := []struct {
		name           string
		logList        []string
		mockResponse   *cloudtrail.LookupEventsOutput
		mockError      error
		expectedResult []string
	}{
		{
			name:    "No export events found",
			logList: []string{"log1", "log2", "log3"},
			mockResponse: &cloudtrail.LookupEventsOutput{
				Events: []types.Event{},
			},
			mockError:      nil,
			expectedResult: []string{"log1", "log2", "log3"},
		},
		{
			name:    "Export events found for some logs",
			logList: []string{"log1", "log2", "log3"},
			mockResponse: &cloudtrail.LookupEventsOutput{
				Events: []types.Event{
					{
						CloudTrailEvent: aws.String(exportEvent),
					},
				},
			},
			mockError:      nil,
			expectedResult: []string{"log2", "log3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mockClient := &mockCloudTrailClient{
				lookupEventsOutput: tt.mockResponse,
				lookupEventsErr:    tt.mockError,
			}

			result := removeExport(tt.logList, mockClient)
			
			if !reflect.DeepEqual(result, tt.expectedResult) {
				t.Errorf("removeExport() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}

// Helper function to create mock CloudTrail event JSON
func createMockCloudTrailEvent(eventName string, requestParams map[string]interface{}) string {
	event := map[string]interface{}{
		"eventName":         eventName,
		"eventTime":         time.Now().Format(time.RFC3339),
		"requestParameters": requestParams,
	}
	
	jsonBytes, _ := json.Marshal(event)
	return string(jsonBytes)
}