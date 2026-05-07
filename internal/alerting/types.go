package alerting

// DenialInfo holds the details of a single denial.
type DenialInfo struct {
	Method  string
	Pattern string
	Reason  string
}
