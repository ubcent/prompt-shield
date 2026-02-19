package mitm

import "net/http"

type Inspector interface {
	InspectRequest(*http.Request) (*http.Request, error)
	InspectResponse(*http.Response) (*http.Response, error)
}

type PassthroughInspector struct{}

func (PassthroughInspector) InspectRequest(r *http.Request) (*http.Request, error) {
	return r, nil
}

func (PassthroughInspector) InspectResponse(r *http.Response) (*http.Response, error) {
	return r, nil
}
