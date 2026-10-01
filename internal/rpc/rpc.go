// Package rpc parses JSON-RPC 2.0 requests.
//
// Strict mode exists because parser differentials are a classic smuggling
// route: if the gateway and the tool server read the same bytes differently,
// the gateway checks one request and the tool runs another. Strict mode:
//   - rejects duplicate keys, including keys that differ only in case
//     (Go's encoding/json matches struct fields case-insensitively and keeps
//     the last duplicate, so {"name":"a","NAME":"b"} would be ambiguous);
//   - rejects batches, excessive nesting, invalid UTF-8 and unknown fields;
//   - is paired with re-serialisation: the gateway forwards what it parsed and
//     checked, never the raw bytes it received.
package rpc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Request is a JSON-RPC 2.0 request as sent by an MCP client.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// IsNotification reports whether the request has no id and therefore expects no response.
func (r *Request) IsNotification() bool { return len(r.ID) == 0 }

// ToolCallParams are the parameters of an MCP tools/call request.
type ToolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
	Meta      map[string]any `json:"_meta,omitempty"`
}

// ParseError carries a stable reason code for the audit log.
type ParseError struct {
	Code string
	Msg  string
}

// Error returns the reason code and message.
func (e *ParseError) Error() string { return e.Code + ": " + e.Msg }

func perr(code, format string, a ...any) error {
	return &ParseError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Code returns the stable reason code of a parse error, for the audit log.
func Code(err error) string {
	var pe *ParseError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return "malformed_request"
}

// ParseStrict validates structure before decoding into typed structs.
func ParseStrict(body []byte, maxDepth int) (*Request, error) {
	if !utf8.Valid(body) {
		return nil, perr("invalid_utf8", "request body is not valid UTF-8")
	}
	if err := CheckStructure(body, maxDepth); err != nil {
		return nil, err
	}
	var req Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return nil, perr("unknown_field", "%v", err)
	}
	if req.JSONRPC != "2.0" {
		return nil, perr("invalid_jsonrpc", "jsonrpc must be \"2.0\"")
	}
	if req.Method == "" {
		return nil, perr("invalid_jsonrpc", "method is required")
	}
	return &req, nil
}

// ParseLenient is what a typical proxy does. Used only by the baseline profiles.
func ParseLenient(body []byte) (*Request, error) {
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, perr("malformed_request", "%v", err)
	}
	return &req, nil
}

// ParseToolCall decodes tools/call params. Strict mode rejects unknown fields.
func ParseToolCall(raw json.RawMessage, strict bool) (*ToolCallParams, error) {
	if len(raw) == 0 {
		return nil, perr("invalid_params", "tools/call requires params")
	}
	var p ToolCallParams
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if strict {
		dec.DisallowUnknownFields()
	}
	if err := dec.Decode(&p); err != nil {
		return nil, perr("invalid_params", "%v", err)
	}
	if p.Name == "" {
		return nil, perr("invalid_params", "tool name is required")
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}
	return &p, nil
}

type frame struct {
	object    bool
	expectKey bool
	keys      map[string]struct{}
}

// CheckStructure walks the token stream once, checking duplicates and depth.
func CheckStructure(body []byte, maxDepth int) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var stack []*frame
	topValues := 0
	first := true

	endValue := func() {
		if len(stack) == 0 {
			topValues++
			return
		}
		if top := stack[len(stack)-1]; top.object {
			top.expectKey = true
		}
	}

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return perr("malformed_json", "%v", err)
		}
		if first {
			first = false
			if d, ok := tok.(json.Delim); !ok || d != '{' {
				if ok && d == '[' {
					return perr("batch_not_supported", "JSON-RPC batches are rejected")
				}
				return perr("invalid_jsonrpc", "request must be a JSON object")
			}
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{', '[':
				stack = append(stack, &frame{object: t == '{', expectKey: t == '{', keys: map[string]struct{}{}})
				if len(stack) > maxDepth {
					return perr("too_deep", "nesting deeper than %d levels", maxDepth)
				}
			case '}', ']':
				stack = stack[:len(stack)-1]
				endValue()
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				top := stack[n-1]
				folded := strings.ToLower(t)
				if _, dup := top.keys[folded]; dup {
					return perr("duplicate_key", "duplicate or case-variant key %q", t)
				}
				top.keys[folded] = struct{}{}
				top.expectKey = false
				continue
			}
			endValue()
		default:
			endValue()
		}
	}
	if topValues != 1 {
		return perr("malformed_json", "expected exactly one JSON value")
	}
	return nil
}
