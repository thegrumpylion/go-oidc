package device

import "net/http"

type request struct {
	scopes string
}

func newRequest(r *http.Request) request {
	return request{
		scopes: r.PostFormValue("scope"),
	}
}

type response struct {
	DeviceCode              string `json:"device_code,omitempty"`
	UserCode                string `json:"user_code,omitempty"`
	VerificationURI         string `json:"verification_uri,omitempty"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in,omitempty"`
	Interval                int    `json:"interval,omitempty"`
}
