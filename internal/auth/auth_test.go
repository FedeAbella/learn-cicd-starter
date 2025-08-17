package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	cases := []struct {
		input       http.Header
		expected    string
		expectedErr error
	}{
		{
			input:       http.Header{},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			input: http.Header{
				"Content-Type": {"application/json"},
			},
			expected:    "",
			expectedErr: ErrNoAuthHeaderIncluded,
		},
		{
			input: http.Header{
				"Authorization": {"Bearer thisissometoken"},
			},
			expected:    "",
			expectedErr: ErrMalformedAuthHeader,
		},
		{
			input: http.Header{
				"Authorization": {"ApiKey thisissomeapikey"},
			},
			expected:    "thisissomeapikey",
			expectedErr: nil,
		},
	}

	for _, c := range cases {
		apiKey, err := GetAPIKey(c.input)
		if err != nil {
			if c.expectedErr == nil {
				t.Errorf(
					"method returned unexpected error %v but case had %v\n",
					err,
					c.expectedErr,
				)
			}
			if !errors.Is(err, c.expectedErr) {
				t.Errorf(
					"method returned wrong error message %v but case had %v\n",
					err.Error(),
					c.expectedErr.Error(),
				)
			}
			continue
		}
		if apiKey == "" {
			t.Errorf("method did not return apiKey or error")
		}
		if apiKey != c.expected {
			t.Errorf("method returned unexpected api key %s but case had %s", apiKey, c.expected)
		}
	}
}
