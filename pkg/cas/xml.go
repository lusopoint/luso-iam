// Package cas defines the CAS 2.0 / 3.0 service-response XML envelopes
// produced by the validate endpoints. Kept in pkg/ so external Go
// consumers (e.g. clients building a CAS mock for tests) can reuse it.
//
// CAS 2.0 vs 3.0:
//
//   - CAS 2.0 returns only <cas:user>username</cas:user>.
//   - CAS 3.0 (the p3 variant) adds a <cas:attributes> child carrying
//     released user attributes.
//
// We model both with a single struct and only emit the attribute block
// for the 3.0 marshaller.
package cas

import (
	"encoding/xml"
)

// XMLNamespace is the canonical CAS XML namespace.
const XMLNamespace = "http://www.yale.edu/tp/cas"

// SuccessResponse models a successful validation response.
//
//	<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
//	  <cas:authenticationSuccess>
//	    <cas:user>alice</cas:user>
//	    <cas:attributes>           <!-- CAS 3.0 only -->
//	      <cas:email>alice@example.com</cas:email>
//	    </cas:attributes>
//	  </cas:authenticationSuccess>
//	</cas:serviceResponse>
type SuccessResponse struct {
	XMLName    xml.Name
	Namespace  string                  `xml:"xmlns:cas,attr"`
	Success    SuccessBody             `xml:"cas:authenticationSuccess"`
}

// SuccessBody is the inner <cas:authenticationSuccess>.
type SuccessBody struct {
	User       string                  `xml:"cas:user"`
	Attributes *AttributesBody         `xml:"cas:attributes,omitempty"`
}

// AttributesBody is the optional <cas:attributes> block emitted only
// by the CAS 3.0 marshaller.
type AttributesBody struct {
	Entries []Attribute `xml:",any"`
}

// Attribute is one entry inside <cas:attributes>. The XML element name
// is the attribute name (e.g. "cas:email") and the value is the inner
// text.
type Attribute struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

// FailureResponse models an authentication failure response.
//
//	<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
//	  <cas:authenticationFailure code="INVALID_TICKET">
//	    Ticket ST-… not recognized
//	  </cas:authenticationFailure>
//	</cas:serviceResponse>
type FailureResponse struct {
	XMLName   xml.Name
	Namespace string         `xml:"xmlns:cas,attr"`
	Failure   FailureBody    `xml:"cas:authenticationFailure"`
}

// FailureBody is the inner <cas:authenticationFailure>.
type FailureBody struct {
	Code    string `xml:"code,attr"`
	Message string `xml:",chardata"`
}

// Standard failure codes per the CAS protocol.
const (
	FailureInvalidRequest      = "INVALID_REQUEST"
	FailureInvalidTicketSpec   = "INVALID_TICKET_SPEC"
	FailureUnauthorizedService = "UNAUTHORIZED_SERVICE"
	FailureInvalidTicket       = "INVALID_TICKET"
	FailureInvalidService      = "INVALID_SERVICE"
	FailureInternalError       = "INTERNAL_ERROR"
)

// NewSuccess builds a success envelope. If attrs is non-empty an
// <cas:attributes> block is included (CAS 3.0 / p3 form). Pass nil
// for CAS 2.0 callers.
func NewSuccess(username string, attrs map[string]string) SuccessResponse {
	r := SuccessResponse{
		XMLName: xml.Name{
			Space: "",
			Local: "cas:serviceResponse",
		},
		Namespace: XMLNamespace,
		Success: SuccessBody{
			User: username,
		},
	}
	if len(attrs) > 0 {
		body := &AttributesBody{Entries: make([]Attribute, 0, len(attrs))}
		for k, v := range attrs {
			body.Entries = append(body.Entries, Attribute{
				XMLName: xml.Name{Local: "cas:" + k},
				Value:   v,
			})
		}
		r.Success.Attributes = body
	}
	return r
}

// NewFailure builds a failure envelope.
func NewFailure(code, message string) FailureResponse {
	return FailureResponse{
		XMLName: xml.Name{
			Space: "",
			Local: "cas:serviceResponse",
		},
		Namespace: XMLNamespace,
		Failure: FailureBody{
			Code:    code,
			Message: message,
		},
	}
}
