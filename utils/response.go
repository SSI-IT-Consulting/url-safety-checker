package utils

type Response struct {
	URL        string `json:"url,omitempty"`
	Status     string `json:"status"`
	Message    string `json:"message,omitempty"`
	ThreatType string `json:"threat_type,omitempty"`
	Error      *Error `json:"error,omitempty"`
}

type Error struct {
	Code    uint   `json:"code"`
	Message string `json:"message"`
}

func GenerateSafeResponse(url string) Response {
	return Response{
		URL:     url,
		Status:  "safe",
		Message: "The URL is not listed in any threat database.",
		Error:   nil,
	}
}

func GenerateUnsafeResponse(url, threatType string) Response {
	return Response{
		URL:        url,
		Status:     "unsafe",
		Message:    "The provided URL is considered unsafe. Please avoid visiting this site.",
		ThreatType: threatType,
		Error:      nil,
	}
}

func GenerateErrorResponse(code int, err string) Response {
	return Response{
		Status: "error",
		Error: &Error{
			Code:    uint(code),
			Message: err,
		},
	}
}
