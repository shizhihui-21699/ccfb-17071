// Package scenario builds realistic audit streams for evaluation.
//
// Every scenario encodes one of the situations the detector must tell apart:
// legitimate shared NAT egress, provider-service forwarding, serverless
// function traffic, and actual off-instance credential use. If a change makes
// the detector flag the first three or miss the last, a test fails.
package scenario

import (
	"encoding/json"
	"fmt"
	"time"

	"credwatch/internal/model"
)

// Call describes one API call to synthesize.
type Call struct {
	At          time.Duration // relative to base
	Source      string        // source address
	Action      string
	EventName   string
	EventSource string
	ReadOnly    bool
	UserAgent   string
	InvokedBy   string
	KeyID       string
	Session     string
	Principal   string
	ErrorCode   string
}

// Scenario is a named, deterministic stream.
type Scenario struct {
	Name        string
	Description string
	BaseTime    time.Time
	Provider    model.Provider
	Calls       []Call
	// DeliveryLag models audit log latency per call; the event's EventTime is
	// At, but it is delivered Delay after that.
	DeliveryDelay time.Duration
}

func (s Scenario) Raw(t model.Provider) ([]byte, error) {
	return Marshal(s, t)
}

// Marshal renders a scenario's calls as provider-shaped audit records.
func Marshal(s Scenario, provider model.Provider) ([]byte, error) {
	switch provider {
	case model.ProviderAWS:
		return marshalAWS(s)
	case model.ProviderAzure:
		return marshalAzure(s)
	case model.ProviderGCP:
		return marshalGCP(s)
	}
	return nil, fmt.Errorf("scenario: unsupported provider %q", provider)
}

func marshalAWS(s Scenario) ([]byte, error) {
	type rec = map[string]any
	var out []rec
	for _, c := range s.Calls {
		ev := timeAt(s.BaseTime, c.At)
		arn := "arn:aws:iam::111122223333:user/svc"
		if c.Session != "" {
			role := "Role"
			arn = "arn:aws:sts::111122223333:assumed-role/" + role + "/" + c.Session
		}
		ui := rec{
			"type":        "AssumedRole",
			"principalId": c.Principal,
			"arn":         arn,
			"accountId":   "111122223333",
			"accessKeyId": c.KeyID,
		}
		if c.InvokedBy != "" {
			ui["invokedBy"] = c.InvokedBy
		}
		out = append(out, rec{
			"eventVersion":    "1.09",
			"eventID":         eventID(s.Name, c),
			"eventTime":       ev.Format(time.RFC3339),
			"eventSource":     c.EventSource,
			"eventName":       c.EventName,
			"awsRegion":       "us-east-1",
			"sourceIPAddress": c.Source,
			"userAgent":       c.UserAgent,
			"readOnly":        c.ReadOnly,
			"userIdentity":    ui,
			"errorCode":       c.ErrorCode,
			"requestID":       eventID(s.Name, c) + "-req",
		})
	}
	return json.Marshal(map[string]any{"Records": out})
}

func marshalAzure(s Scenario) ([]byte, error) {
	var out []map[string]any
	for _, c := range s.Calls {
		out = append(out, map[string]any{
			"id":              eventID(s.Name, c),
			"time":            timeAt(s.BaseTime, c.At).Format(time.RFC3339Nano),
			"subscriptionId":  "sub-1",
			"operationName":   c.EventName,
			"category":        c.EventSource,
			"resultType":      ifEmpty(c.ErrorCode, "Success"),
			"callerIpAddress": c.Source,
			"correlationId":   eventID(s.Name, c) + "-corr",
			"properties": map[string]any{
				"clientAppId": c.KeyID,
				"userAgent":   c.UserAgent,
			},
		})
	}
	return json.Marshal(out)
}

func marshalGCP(s Scenario) ([]byte, error) {
	var out []map[string]any
	for _, c := range s.Calls {
		out = append(out, map[string]any{
			"insertId":  eventID(s.Name, c),
			"logName":   "projects/proj-1/logs/cloudaudit.googleapis.com%2Factivity",
			"timestamp": timeAt(s.BaseTime, c.At).Format(time.RFC3339Nano),
			"protoPayload": map[string]any{
				"methodName":   c.EventName,
				"serviceName":  c.EventSource,
				"resourceName": "projects/proj-1/zones/us-central1-a/instances/vm-1",
				"authenticationInfo": map[string]any{
					"principalEmail": c.KeyID,
				},
				"requestMetadata": map[string]any{
					"callerIp":                c.Source,
					"callerSuppliedUserAgent": c.UserAgent,
				},
			},
			"trace": eventID(s.Name, c) + "-trace",
		})
	}
	return json.Marshal(out)
}

func timeAt(base time.Time, d time.Duration) time.Time { return base.Add(d) }

func eventID(name string, c Call) string {
	return fmt.Sprintf("%s-%d-%s", name, c.At, c.Source)
}

func ifEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
