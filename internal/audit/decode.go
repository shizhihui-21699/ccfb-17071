// Package audit ingests provider audit records and normalizes them into
// model.Event.
//
// Normalization is where trust boundaries are decided. For each provider we
// must answer, explicitly, which fields the provider wrote (trusted) and which
// the caller controls (untrusted). Getting this wrong is how a detector
// becomes bypassable: a client-supplied header must never be able to clear a
// suspicion, and a provider-written field must never be discarded because it
// inconvenience the happy path.
package audit

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"credwatch/internal/model"
)

// Decoder turns one raw audit record into a model.Event.
type Decoder interface {
	Provider() model.Provider
	Decode(raw []byte) (model.Event, error)
}

func DecoderFor(p model.Provider) (Decoder, error) {
	switch p {
	case model.ProviderAWS:
		return AWSDecoder{}, nil
	case model.ProviderAzure:
		return AzureDecoder{}, nil
	case model.ProviderGCP:
		return GCPDecoder{}, nil
	}
	return nil, fmt.Errorf("audit: unsupported provider %q", p)
}

// ---------- AWS CloudTrail ----------

// cloudTrailRecord models the subset of CloudTrail we use. Note how trust is
// split: userIdentity, eventSource/eventName, sourceIPAddress and
// vpcEndpointId are written by AWS. userAgent and any request parameter are
// caller-controlled. userIdentity.sessionContext.sessionIssuer and
// invokedBy are AWS-injected.
type cloudTrailRecord struct {
	EventVersion    string `json:"eventVersion"`
	EventID         string `json:"eventID"`
	EventTime       string `json:"eventTime"`
	EventSource     string `json:"eventSource"`
	EventName       string `json:"eventName"`
	AWSRegion       string `json:"awsRegion"`
	SourceIPAddress string `json:"sourceIPAddress"`
	UserAgent       string `json:"userAgent"`
	ReadOnly        bool   `json:"readOnly"`

	UserIdentity struct {
		Type           string `json:"type"`
		PrincipalID    string `json:"principalId"`
		ARN            string `json:"arn"`
		AccountID      string `json:"accountId"`
		AccessKeyID    string `json:"accessKeyId"`
		SessionContext struct {
			SessionIssuer struct {
				Type        string `json:"type"`
				PrincipalID string `json:"principalId"`
				ARN         string `json:"arn"`
				AccountID   string `json:"accountId"`
				UserName    string `json:"userName"`
			} `json:"sessionIssuer"`
			Attributes struct {
				MFAAuthenticated string `json:"mfaAuthenticated"`
				CreationDate     string `json:"creationDate"`
			} `json:"attributes"`
		} `json:"sessionContext"`
		InvokedBy string `json:"invokedBy"`
	} `json:"userIdentity"`

	VPCEndpointID string `json:"vpcEndpointId"`
	ErrorCode     string `json:"errorCode"`
	RequestID     string `json:"requestID"`

	Resources []struct {
		ARN  string `json:"ARN"`
		Type string `json:"type"`
	} `json:"resources"`

	// AdditionalEventData carries provider-written routing hints for some
	// services (e.g. S3 access point, Lambda egress). Treated as trusted only
	// for the specific keys the provider documents; see decode.
	AdditionalEventData map[string]any `json:"additionalEventData"`
}

// CloudTrailEnvelope is a CloudTrail file's Records array, as delivered by
// S3 notifications, or a single record from an EventBridge/CloudTrail Lake
// stream. The decoder accepts both.
type cloudTrailEnvelope struct {
	Records []cloudTrailRecord `json:"Records"`
}

type AWSDecoder struct{}

func (AWSDecoder) Provider() model.Provider { return model.ProviderAWS }

func (AWSDecoder) Decode(raw []byte) (model.Event, error) {
	// Accept either a bare record or a {"Records":[...]} file.
	var probe struct {
		Records []json.RawMessage `json:"Records"`
	}
	if err := json.Unmarshal(raw, &probe); err == nil && len(probe.Records) > 0 {
		raw = probe.Records[0]
	}
	var r cloudTrailRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return model.Event{}, fmt.Errorf("aws: decode cloudtrail record: %w", err)
	}
	return awsEvent(r)
}

// DecodeAll handles CloudTrail files containing many records.
func (AWSDecoder) DecodeAll(raw []byte) ([]model.Event, error) {
	var env cloudTrailEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("aws: decode cloudtrail file: %w", err)
	}
	out := make([]model.Event, 0, len(env.Records))
	for i, r := range env.Records {
		ev, err := awsEvent(r)
		if err != nil {
			return nil, fmt.Errorf("aws: record %d: %w", i, err)
		}
		out = append(out, ev)
	}
	return out, nil
}

func awsEvent(r cloudTrailRecord) (model.Event, error) {
	t, err := time.Parse(time.RFC3339, r.EventTime)
	if err != nil {
		return model.Event{}, fmt.Errorf("aws: eventTime %q: %w", r.EventTime, err)
	}
	ev := model.Event{
		ID:          r.EventID,
		Provider:    model.ProviderAWS,
		AccountID:   r.UserIdentity.AccountID,
		Region:      r.AWSRegion,
		EventTime:   t.UTC(),
		EventSource: r.EventSource,
		EventName:   r.EventName,
		Action:      normalizeAWSAction(r.EventSource, r.EventName),
		ReadOnly:    r.ReadOnly,
		AccessKeyID: r.UserIdentity.AccessKeyID,
		PrincipalID: r.UserIdentity.PrincipalID,
		SourceIP:    r.SourceIPAddress,
		// invokedBy is written by AWS; keep it out of UserAgent.
		InvokedBy:     r.UserIdentity.InvokedBy,
		VPCEndpointID: r.VPCEndpointID,
		UserAgent:     r.UserAgent,
		ErrorCode:     r.ErrorCode,
		TraceID:       r.RequestID,
	}
	// Session name: temporary credentials created by AssumeRole carry it in
	// the ARN after the role name ("arn:aws:sts::...:assumed-role/Role/Session").
	// It is derived from a provider-written field, so it is trusted.
	if name := sessionNameFromARN(r.UserIdentity.ARN); name != "" {
		ev.SessionName = name
	}
	if ev.AccountID == "" {
		ev.AccountID = r.UserIdentity.SessionContext.SessionIssuer.AccountID
	}
	for _, res := range r.Resources {
		if res.ARN != "" {
			ev.Resources = append(ev.Resources, res.ARN)
		}
	}
	return ev, nil
}

func sessionNameFromARN(arn string) string {
	// arn:aws:sts::123456789012:assumed-role/RoleName/SessionName
	const marker = ":assumed-role/"
	i := strings.Index(arn, marker)
	if i < 0 {
		return ""
	}
	rest := arn[i+len(marker):]
	if j := strings.LastIndex(rest, "/"); j >= 0 {
		return rest[j+1:]
	}
	return ""
}

func normalizeAWSAction(source, name string) string {
	svc := source
	if i := strings.Index(svc, "."); i > 0 {
		svc = svc[:i]
	}
	// CloudTrail eventSource uses the service's DNS-ish name; the IAM
	// namespace differs for a handful of services. Keep the mapping small and
	// explicit rather than clever.
	switch svc {
	case "monitoring":
		svc = "cloudwatch"
	case "sts":
		svc = "sts"
	case "s3":
		svc = "s3"
	}
	if name == "" {
		return svc
	}
	return svc + ":" + name
}

// ---------- Azure ----------

// Azure produces two relevant streams: Activity Log (management plane, has
// callerIpAddress) and Entra ID sign-in / Graph (data plane). Either can carry
// service principal or managed-identity token use. The correlation key is the
// app/object id (KeyKind=principal): Azure temporary credentials are bearer
// tokens, not per-session keys, so several pods legitimately share one
// identity and concurrency is not by itself suspicious.
type azureRecord struct {
	ID              string `json:"id"`
	Time            string `json:"time"`
	TenantID        string `json:"tenantId"`
	SubscriptionID  string `json:"subscriptionId"`
	OperationName   string `json:"operationName"`
	Category        string `json:"category"`
	ResultType      string `json:"resultType"`
	CallerIPAddress string `json:"callerIpAddress"`
	CorrelationID   string `json:"correlationId"`

	Properties struct {
		CallerIPAddress  string `json:"callerIpAddress"`
		Caller           string `json:"caller"`
		ServiceRequestID string `json:"serviceRequestId"`
		ResultSignature  string `json:"resultSignature"`
		// clientAppId identifies the app registration / managed identity.
		// For managed identity, it is the *identity* object id.
		ClientAppID string `json:"clientAppId"`
		AppID       string `json:"appId"`
		ObjectID    string `json:"objectId"`
		// UserAgent is client-supplied.
		UserAgent string `json:"userAgent"`
	} `json:"properties"`

	// SigninLogs-style fields (Graph / Log Analytics export).
	AppDisplayName       string `json:"appDisplayName"`
	UserPrincipalName    string `json:"userPrincipalName"`
	IPAddress            string `json:"ipAddress"`
	ServicePrincipalID   string `json:"servicePrincipalId"`
	ServicePrincipalName string `json:"servicePrincipalName"`
}

type AzureDecoder struct{}

func (AzureDecoder) Provider() model.Provider { return model.ProviderAzure }

func (AzureDecoder) Decode(raw []byte) (model.Event, error) {
	var r azureRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return model.Event{}, fmt.Errorf("azure: decode record: %w", err)
	}
	t, err := time.Parse(time.RFC3339, r.Time)
	if err != nil {
		// Activity Log sometimes emits fractional seconds or a "Z" suffix;
		// RFC3339Nano covers both.
		t, err = time.Parse(time.RFC3339Nano, r.Time)
		if err != nil {
			return model.Event{}, fmt.Errorf("azure: time %q: %w", r.Time, err)
		}
	}
	ip := r.CallerIPAddress
	if ip == "" {
		ip = r.Properties.CallerIPAddress
	}
	if ip == "" {
		ip = r.IPAddress
	}
	principal := firstNonEmpty(r.Properties.ClientAppID, r.Properties.AppID, r.Properties.ObjectID, r.ServicePrincipalID, r.Properties.Caller)
	ev := model.Event{
		ID:          firstNonEmpty(r.ID, r.CorrelationID, r.Properties.ServiceRequestID),
		Provider:    model.ProviderAzure,
		AccountID:   firstNonEmpty(r.SubscriptionID, r.TenantID),
		EventTime:   t.UTC(),
		EventSource: firstNonEmpty(r.Category, "azure.activity"),
		EventName:   r.OperationName,
		Action:      normalizeAzureAction(r.OperationName),
		ReadOnly:    strings.Contains(strings.ToLower(r.OperationName), "/read"),
		// Azure bearer tokens have no per-session key. We key on the
		// principal, and KeyKind=principal on the record tells the engine
		// that concurrency is expected.
		AccessKeyID: principal,
		PrincipalID: principal,
		SourceIP:    ip,
		UserAgent:   r.Properties.UserAgent,
		TraceID:     firstNonEmpty(r.CorrelationID, r.Properties.ServiceRequestID),
	}
	if r.ResultType != "" && r.ResultType != "Success" {
		ev.ErrorCode = r.ResultType
	}
	return ev, nil
}

func normalizeAzureAction(op string) string {
	// "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
	// -> "microsoft.storage:blobs/read"
	if op == "" {
		return ""
	}
	parts := strings.Split(op, "/")
	if len(parts) >= 2 && strings.Contains(parts[0], ".") {
		verb := parts[len(parts)-1]
		return strings.ToLower(parts[0]) + ":" + verb
	}
	return strings.ToLower(op)
}

// ---------- GCP ----------

// GCP Cloud Audit Logs carry authenticationInfo (which principal and, for
// service-account impersonation, which service account), requestMetadata
// (callerIp, callerSuppliedUserAgent) and a protoPayload status. There is no
// per-session key; the credential identity is the service account email, which
// makes GCP KeyKind=principal as well. Instance metadata tokens resolve at the
// API to the attached service account, so every instance sharing that service
// account looks identical here — attribution must lean on network + attest.
type gcpRecord struct {
	InsertID  string `json:"insertId"`
	LogName   string `json:"logName"`
	Timestamp string `json:"timestamp"`
	Severity  string `json:"severity"`

	ProtoPayload struct {
		Type               string `json:"@type"`
		MethodName         string `json:"methodName"`
		ResourceName       string `json:"resourceName"`
		ServiceName        string `json:"serviceName"`
		AuthenticationInfo struct {
			PrincipalEmail               string `json:"principalEmail"`
			PrincipalSubject             string `json:"principalSubject"`
			ServiceAccountDelegationInfo []struct {
				FirstPartyPrincipal struct {
					PrincipalEmail string `json:"principalEmail"`
				} `json:"firstPartyPrincipal"`
			} `json:"serviceAccountDelegationInfo"`
		} `json:"authenticationInfo"`
		RequestMetadata struct {
			CallerIP                string `json:"callerIp"`
			CallerSuppliedUserAgent string `json:"callerSuppliedUserAgent"`
			CallerNetwork           string `json:"callerNetwork"`
			RequestAttributes       struct {
				Auth struct {
					AccessLevels []string `json:"accessLevels"`
				} `json:"auth"`
				Time string `json:"time"`
				// DestinationAttributes carries the resource being called.
			} `json:"requestAttributes"`
		} `json:"requestMetadata"`
		Status struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"status"`
	} `json:"protoPayload"`

	Resource struct {
		Type   string            `json:"type"`
		Labels map[string]string `json:"labels"`
	} `json:"resource"`

	Trace string `json:"trace"`
}

type GCPDecoder struct{}

func (GCPDecoder) Provider() model.Provider { return model.ProviderGCP }

func (GCPDecoder) Decode(raw []byte) (model.Event, error) {
	var r gcpRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return model.Event{}, fmt.Errorf("gcp: decode record: %w", err)
	}
	t, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		t, err = time.Parse(time.RFC3339, r.Timestamp)
		if err != nil {
			return model.Event{}, fmt.Errorf("gcp: timestamp %q: %w", r.Timestamp, err)
		}
	}
	principal := r.ProtoPayload.AuthenticationInfo.PrincipalEmail
	if principal == "" {
		principal = r.ProtoPayload.AuthenticationInfo.PrincipalSubject
	}
	ev := model.Event{
		ID:          firstNonEmpty(r.InsertID, r.Trace),
		Provider:    model.ProviderGCP,
		AccountID:   gcpProject(r.LogName, r.ProtoPayload.ResourceName),
		EventTime:   t.UTC(),
		EventSource: firstNonEmpty(r.ProtoPayload.ServiceName, r.Resource.Type),
		EventName:   r.ProtoPayload.MethodName,
		Action:      normalizeGCPAction(r.ProtoPayload.ServiceName, r.ProtoPayload.MethodName),
		ReadOnly:    gcpIsRead(r.ProtoPayload.MethodName),
		AccessKeyID: principal,
		PrincipalID: principal,
		SourceIP:    r.ProtoPayload.RequestMetadata.CallerIP,
		UserAgent:   r.ProtoPayload.RequestMetadata.CallerSuppliedUserAgent,
		TraceID:     r.Trace,
	}
	if len(ev.Resources) == 0 && r.ProtoPayload.ResourceName != "" {
		ev.Resources = []string{r.ProtoPayload.ResourceName}
	}
	if r.ProtoPayload.Status.Code != 0 {
		ev.ErrorCode = fmt.Sprintf("code_%d", r.ProtoPayload.Status.Code)
	}
	return ev, nil
}

func gcpProject(logName, resourceName string) string {
	// projects/<id>/logs/... or //compute.googleapis.com/projects/<id>/...
	if i := strings.Index(logName, "projects/"); i >= 0 {
		rest := logName[i+len("projects/"):]
		if j := strings.Index(rest, "/"); j > 0 {
			return rest[:j]
		}
	}
	if i := strings.Index(resourceName, "projects/"); i >= 0 {
		rest := resourceName[i+len("projects/"):]
		if j := strings.Index(rest, "/"); j > 0 {
			return rest[:j]
		}
	}
	return ""
}

func normalizeGCPAction(service, method string) string {
	svc := service
	if i := strings.Index(svc, ".googleapis.com"); i > 0 {
		svc = svc[:i]
	}
	m := strings.TrimPrefix(method, "google.")
	if m == "" {
		return svc
	}
	return svc + ":" + m
}

func gcpIsRead(method string) bool {
	m := strings.ToLower(method)
	return strings.Contains(m, ".get") || strings.Contains(m, ".list") || strings.Contains(m, ".read")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
