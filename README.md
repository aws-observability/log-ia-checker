# Infrequent Access Check for CloudWatch Log Group

This project retrieves and filters CloudWatch log groups based on a list of conditions. It outputs a list of log groups that are good candidates for transitionsto Infrequent Access (IA).

## Why?
CloudWatch logs has a log class called [Infrequent Access](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html). This Log class is 50% cheaper on ingestion but it does not contain call the capabilities
of a standard log group. Using this command line utility, we can check all logs in a region to see if they would be good candidates for transition to IA. At this time it is not possible to programmatically convert a log group from standard to IA
therefore that is considered out of scope. Using this tool though we can get a list of candidates to review further to see if they can be recreated as IA log groups.

## Prerequisites

### 1. Go (Golang)
- You must have [Go](https://golang.org/dl/) installed. This project is written in Go, and you will need to run Go programs and install dependencies.
- To check if Go is installed, run:
  ```bash
  go version
  ```

### 2. AWS CLI Credentials
- AWS credentials should be configured using the AWS [CLI](https://docs.aws.amazon.com/cli/v1/userguide/cli-chap-configure.html). The Go SDK uses these credentials to authenticate requests to AWS services (CloudWatch Logs and CloudTrail)
- Ensure you have access to perform read operations on both CloudWatch Logs and CloudTrail.

## Setup
1. Clone the repo
```
git clone https://github.com/aws-observability/log-ia-checker.git
cd log-ia-checker
```

2. Install Go Packages
```
go mod tidy
```

3. Run the Program
```
go run . OPTIONS REGION
```

For Example:
```
go run . -outfile ia.txt us-west-2
```

The program accepts the following parameters:
- `aws-region`: AWS region to check log groups in (optional if AWS_REGION environment variable is set)
- `output-file`: File to write results to (defaults to 'ia.txt' if not provided)

Examples:
```
# Specify both region and output file
go run . -outfile ia.txt us-west-2

# Use AWS_REGION environment variable and default output file
export AWS_REGION=us-west-2
go run .

# Specify region but use default output file
go run . us-east-1
```

## Notes
Currently, the utility only can check one region in one account at a time.

At this time we check for the following criteria to exclude a log group from consdieration for IA:

- Metric Filters
- Subscription Filters
- Anomaly Detectors
- Used for lambda or container insights
- Is already standard
- Field Indexes
- Data Protection Policies
- LiveTail Events in the last 30 days
- S3 export jobs in the last 30 days

## License
This project is licensed under the MIT License - see the LICENSE file for details.
