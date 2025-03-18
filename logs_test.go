package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatchLogsAPI defines the interface for CloudWatch Logs client operations
type CloudWatchLogsAPI interface {
	DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	DescribeFieldIndexes(ctx context.Context, params *cloudwatchlogs.DescribeFieldIndexesInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeFieldIndexesOutput, error)
	DescribeSubscriptionFilters(ctx context.Context, params *cloudwatchlogs.DescribeSubscriptionFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeSubscriptionFiltersOutput, error)
	ListLogAnomalyDetectors(ctx context.Context, params *cloudwatchlogs.ListLogAnomalyDetectorsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListLogAnomalyDetectorsOutput, error)
}

// Mock CloudWatchLogs client for testing
type mockCloudWatchLogsClient struct {
	CloudWatchLogsAPI
	describeLogGroupsOutput *cloudwatchlogs.DescribeLogGroupsOutput
	describeLogGroupsErr    error
	
	describeFieldIndexesOutput *cloudwatchlogs.DescribeFieldIndexesOutput
	describeFieldIndexesErr    error
	
	describeSubscriptionFiltersOutput *cloudwatchlogs.DescribeSubscriptionFiltersOutput
	describeSubscriptionFiltersErr    error
	
	listLogAnomalyDetectorsOutput *cloudwatchlogs.ListLogAnomalyDetectorsOutput
	listLogAnomalyDetectorsErr    error
}

func (m *mockCloudWatchLogsClient) DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error) {
	return m.describeLogGroupsOutput, m.describeLogGroupsErr
}

func (m *mockCloudWatchLogsClient) DescribeFieldIndexes(ctx context.Context, params *cloudwatchlogs.DescribeFieldIndexesInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeFieldIndexesOutput, error) {
	return m.describeFieldIndexesOutput, m.describeFieldIndexesErr
}

func (m *mockCloudWatchLogsClient) DescribeSubscriptionFilters(ctx context.Context, params *cloudwatchlogs.DescribeSubscriptionFiltersInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeSubscriptionFiltersOutput, error) {
	return m.describeSubscriptionFiltersOutput, m.describeSubscriptionFiltersErr
}

func (m *mockCloudWatchLogsClient) ListLogAnomalyDetectors(ctx context.Context, params *cloudwatchlogs.ListLogAnomalyDetectorsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.ListLogAnomalyDetectorsOutput, error) {
	return m.listLogAnomalyDetectorsOutput, m.listLogAnomalyDetectorsErr
}

func TestCheckLogGroup(t *testing.T) {
	tests := []struct {
		name     string
		logGroup types.LogGroup
		expected bool
	}{
		{
			name: "Log group with metric filter",
			logGroup: types.LogGroup{
				LogGroupName:     aws.String("test-log-group"),
				MetricFilterCount: aws.Int32(1),
			},
			expected: true,
		},
		{
			name: "Log group with data protection policy",
			logGroup: types.LogGroup{
				LogGroupName:        aws.String("test-log-group"),
				DataProtectionStatus: types.DataProtectionStatusActivated,
			},
			expected: true,
		},
		{
			name: "Log group already in IA",
			logGroup: types.LogGroup{
				LogGroupName:  aws.String("test-log-group"),
				LogGroupClass: types.LogGroupClassInfrequentAccess,
			},
			expected: true,
		},
		{
			name: "Log group with insights in name",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("lambda-insights-log-group"),
			},
			expected: true,
		},
		{
			name: "Log group with containerinsights in name",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("containerinsights-log-group"),
			},
			expected: true,
		},
		{
			name: "Log group with no special conditions",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("regular-log-group"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checkLogGroup(tt.logGroup)
			if result != tt.expected {
				t.Errorf("checkLogGroup() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIsIA(t *testing.T) {
	tests := []struct {
		name     string
		logGroup types.LogGroup
		expected bool
	}{
		{
			name: "Log group in IA class",
			logGroup: types.LogGroup{
				LogGroupClass: types.LogGroupClassInfrequentAccess,
			},
			expected: true,
		},
		{
			name: "Log group in standard class",
			logGroup: types.LogGroup{
				LogGroupClass: types.LogGroupClassStandard,
			},
			expected: false,
		},
		{
			name:     "Log group with no class specified",
			logGroup: types.LogGroup{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIA(tt.logGroup)
			if result != tt.expected {
				t.Errorf("isIA() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasMetricFilter(t *testing.T) {
	tests := []struct {
		name     string
		logGroup types.LogGroup
		expected bool
	}{
		{
			name: "Log group with metric filters",
			logGroup: types.LogGroup{
				MetricFilterCount: aws.Int32(2),
			},
			expected: true,
		},
		{
			name: "Log group with no metric filters",
			logGroup: types.LogGroup{
				MetricFilterCount: aws.Int32(0),
			},
			expected: false,
		},
		{
			name:     "Log group with nil metric filter count",
			logGroup: types.LogGroup{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasMetricFilter(tt.logGroup)
			if result != tt.expected {
				t.Errorf("hasMetricFilter() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasDataProtectionPolicy(t *testing.T) {
	tests := []struct {
		name     string
		logGroup types.LogGroup
		expected bool
	}{
		{
			name: "Log group with activated data protection",
			logGroup: types.LogGroup{
				DataProtectionStatus: types.DataProtectionStatusActivated,
			},
			expected: true,
		},
		{
			name: "Log group with no data protection",
			logGroup: types.LogGroup{
				// No DataProtectionStatus set
			},
			expected: false,
		},
		{
			name:     "Log group with no data protection status",
			logGroup: types.LogGroup{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasDataProtectionPolicy(tt.logGroup)
			if result != tt.expected {
				t.Errorf("hasDataProtectionPolicy() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestHasInsights(t *testing.T) {
	tests := []struct {
		name     string
		logGroup types.LogGroup
		expected bool
	}{
		{
			name: "Log group with lambda-insights in name",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("/aws/lambda-insights/my-function"),
			},
			expected: true,
		},
		{
			name: "Log group with containerinsights in name",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("/aws/containerinsights/my-cluster"),
			},
			expected: true,
		},
		{
			name: "Regular log group",
			logGroup: types.LogGroup{
				LogGroupName: aws.String("/aws/lambda/my-function"),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasInsights(tt.logGroup)
			if result != tt.expected {
				t.Errorf("hasInsights() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestFetchIndexPoliciesForBatch(t *testing.T) {
	tests := []struct {
		name           string
		batch          []string
		mockResponse   *cloudwatchlogs.DescribeFieldIndexesOutput
		mockError      error
		expectedResult []string
	}{
		{
			name:  "No log groups have index policies",
			batch: []string{"log1", "log2", "log3"},
			mockResponse: &cloudwatchlogs.DescribeFieldIndexesOutput{
				FieldIndexes: []types.FieldIndex{},
			},
			mockError:      nil,
			expectedResult: []string{"log1", "log2", "log3"},
		},
		{
			name:  "Some log groups have index policies",
			batch: []string{"log1", "log2", "log3"},
			mockResponse: &cloudwatchlogs.DescribeFieldIndexesOutput{
				FieldIndexes: []types.FieldIndex{
					{
						LogGroupIdentifier: aws.String("log1"),
					},
				},
			},
			mockError:      nil,
			expectedResult: []string{"log2", "log3"},
		},
		{
			name:  "All log groups have index policies",
			batch: []string{"log1", "log2"},
			mockResponse: &cloudwatchlogs.DescribeFieldIndexesOutput{
				FieldIndexes: []types.FieldIndex{
					{
						LogGroupIdentifier: aws.String("log1"),
					},
					{
						LogGroupIdentifier: aws.String("log2"),
					},
				},
			},
			mockError:      nil,
			expectedResult: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mockClient := &mockCloudWatchLogsClient{
				describeFieldIndexesOutput: tt.mockResponse,
				describeFieldIndexesErr:    tt.mockError,
			}

			result := fetchIndexPoliciesForBatch(tt.batch, mockClient)
			
			// Sort both slices to ensure consistent comparison
			if !reflect.DeepEqual(result, tt.expectedResult) {
				// Special case for empty slices
				if len(result) == 0 && len(tt.expectedResult) == 0 {
					// Both are empty, so they're equal
					return
				}
				t.Errorf("fetchIndexPoliciesForBatch() = %v, want %v", result, tt.expectedResult)
			}
		})
	}
}