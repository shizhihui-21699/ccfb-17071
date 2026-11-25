package audit_test

import (
	"testing"
	"time"

	"credwatch/internal/audit"
	"credwatch/internal/model"
)

func TestAWSDecodeTrustBoundary(t *testing.T) {
	raw := []byte(`{
      "eventID":"1","eventTime":"2026-03-01T11:58:00Z","eventSource":"s3.amazonaws.com",
      "eventName":"ReplicateObject","awsRegion":"us-east-1","sourceIPAddress":"52.94.1.1",
      "userAgent":"some-client/1.0","readOnly":false,
      "userIdentity":{"type":"AssumedRole","accountId":"111122223333","accessKeyId":"ASIA1",
        "arn":"arn:aws:sts::111122223333:assumed-role/web-role/sess-a","invokedBy":"s3.amazonaws.com"},
      "vpcEndpointId":"vpce-1"}`)
	dec := audit.AWSDecoder{}
	ev, err := dec.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.InvokedBy != "s3.amazonaws.com" {
		t.Fatalf("invokedBy must be preserved as trusted metadata, got %q", ev.InvokedBy)
	}
	if ev.UserAgent != "some-client/1.0" {
		t.Fatalf("user agent must be preserved separately, got %q", ev.UserAgent)
	}
	if ev.SessionName != "sess-a" {
		t.Fatalf("session name should be derived from the ARN, got %q", ev.SessionName)
	}
	if ev.VPCEndpointID != "vpce-1" {
		t.Fatalf("vpc endpoint id lost: %q", ev.VPCEndpointID)
	}
	if ev.Action != "s3:ReplicateObject" {
		t.Fatalf("action normalization: %q", ev.Action)
	}
}

func TestAWSDecodeFile(t *testing.T) {
	raw := []byte(`{"Records":[
      {"eventID":"a","eventTime":"2026-03-01T11:58:00Z","eventSource":"s3.amazonaws.com","eventName":"GetObject"},
      {"eventID":"b","eventTime":"2026-03-01T11:58:01Z","eventSource":"ec2.amazonaws.com","eventName":"RunInstances"}
    ]}`)
	evs, err := (audit.AWSDecoder{}).DecodeAll(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("want 2 events, got %d", len(evs))
	}
	if evs[1].Action != "ec2:RunInstances" {
		t.Fatalf("action: %q", evs[1].Action)
	}
}

func TestAzureDecodePrincipalScoped(t *testing.T) {
	raw := []byte(`{
      "id":"az-1","time":"2026-03-01T11:58:00.123Z","subscriptionId":"sub-1",
      "operationName":"Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
      "category":"Administrative","resultType":"Success","callerIpAddress":"198.51.100.5",
      "properties":{"clientAppId":"app-123","userAgent":"azure-sdk/1"}}`)
	ev, err := (audit.AzureDecoder{}).Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	// Azure bearer tokens have no per-session key: the principal is the key.
	if ev.AccessKeyID != "app-123" {
		t.Fatalf("azure key should be the app id, got %q", ev.AccessKeyID)
	}
	if ev.SourceIP != "198.51.100.5" {
		t.Fatalf("caller ip: %q", ev.SourceIP)
	}
	if ev.UserAgent != "azure-sdk/1" {
		t.Fatalf("user agent: %q", ev.UserAgent)
	}
	if !ev.EventTime.Equal(time.Date(2026, 3, 1, 11, 58, 0, 123000000, time.UTC)) {
		t.Fatalf("time parse with fractional seconds: %v", ev.EventTime)
	}
}

func TestGCPDecodePrincipalAndIP(t *testing.T) {
	raw := []byte(`{
      "insertId":"g1","logName":"projects/proj-1/logs/cloudaudit.googleapis.com%2Factivity",
      "timestamp":"2026-03-01T11:58:00.500Z",
      "protoPayload":{"methodName":"storage.objects.get","serviceName":"storage.googleapis.com",
        "resourceName":"projects/proj-1/buckets/b1",
        "authenticationInfo":{"principalEmail":"sa@proj-1.iam.gserviceaccount.com"},
        "requestMetadata":{"callerIp":"198.51.100.9","callerSuppliedUserAgent":"google-api-go/1"}}}`)
	ev, err := (audit.GCPDecoder{}).Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.AccessKeyID != "sa@proj-1.iam.gserviceaccount.com" {
		t.Fatalf("gcp key should be the service account, got %q", ev.AccessKeyID)
	}
	if ev.SourceIP != "198.51.100.9" {
		t.Fatalf("caller ip: %q", ev.SourceIP)
	}
	if ev.AccountID != "proj-1" {
		t.Fatalf("project id: %q", ev.AccountID)
	}
	if !ev.ReadOnly {
		t.Fatal("storage.objects.get should be read-only")
	}
}

func TestUnsupportedProvider(t *testing.T) {
	if _, err := audit.DecoderFor(model.Provider("oracle")); err == nil {
		t.Fatal("expected error for unsupported provider")
	}
}
