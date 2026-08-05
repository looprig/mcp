// These tables drive the sampling conversions with everything a server can
// send: the shapes MCP allows, the shapes it does not, and the boundary of every
// bound. The wire half — what this module advertises, and what a server actually
// gets back — is in session_sample_test.go, because only a server can observe
// it.

package protocol_test

import (
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/looprig/mcp/internal/limits"
	"github.com/looprig/mcp/internal/protocol"
)

// sampleBounds is a small, exact bound so a table can sit on its edge.
func sampleBounds() protocol.Bounds {
	return protocol.Bounds{MaxTextBytes: 32}
}

// textMsg builds a well-formed text message.
//
//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
func textMsg(role, text string) *mcp.SamplingMessage {
	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	return &mcp.SamplingMessage{Role: mcp.Role(role), Content: &mcp.TextContent{Text: text}}
}

func TestFromSDKCreateMessageParams(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		params  *mcp.CreateMessageParams
		want    protocol.SampleRequest
		wantErr bool
	}{
		{
			name: "happy path",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens:    100,
				SystemPrompt: "be brief",
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{textMsg("user", "hi")},
			},
			want: protocol.SampleRequest{
				SystemPrompt: "be brief",
				Messages:     []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: "hi"}},
				MaxTokens:    100,
			},
		},
		{
			name: "both roles",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens: 1,
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{
					textMsg("user", "a"),
					textMsg("assistant", "b"),
				},
			},
			want: protocol.SampleRequest{
				Messages: []protocol.SampleMessage{
					{Role: protocol.SampleRoleUser, Text: "a"},
					{Role: protocol.SampleRoleAssistant, Text: "b"},
				},
				MaxTokens: 1,
			},
		},
		{
			// The server's steering fields are dropped, not carried. This is the
			// design's "the application supplies model selection": there is no
			// field on SampleRequest for a server's preference, so a handler
			// cannot honor one.
			name: "server steering fields are dropped",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens: 5,
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{textMsg("user", "hi")},
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				ModelPreferences: &mcp.ModelPreferences{Hints: []*mcp.ModelHint{{Name: "expensive-model"}}},
				Temperature:      2,
				StopSequences:    []string{"stop"},
				IncludeContext:   "allServers",
				Metadata:         map[string]any{"k": "v"},
			},
			want: protocol.SampleRequest{
				Messages:  []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: "hi"}},
				MaxTokens: 5,
			},
		},
		{
			name:    "nil params",
			params:  nil,
			wantErr: true,
		},
		{
			name: "no messages",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: 1, Messages: nil},
			wantErr: true,
		},
		{
			name: "nil message",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: 1, Messages: []*mcp.SamplingMessage{nil}},
			wantErr: true,
		},
		{
			name: "unknown role",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: 1, Messages: []*mcp.SamplingMessage{textMsg("system", "hi")}},
			wantErr: true,
		},
		{
			name: "empty role",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: 1, Messages: []*mcp.SamplingMessage{textMsg("", "hi")}},
			wantErr: true,
		},
		{
			// Refused, not dropped: a conversation with a message removed is a
			// different conversation from the one the server sent.
			name: "non-text content is refused",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens: 1,
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{
					{Role: "user", Content: &mcp.ImageContent{Data: []byte{1}, MIMEType: "image/png"}},
				},
			},
			wantErr: true,
		},
		{
			name: "nil content",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens: 1,
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{{Role: "user", Content: nil}},
			},
			wantErr: true,
		},
		{
			name: "zero maxTokens",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: 0, Messages: []*mcp.SamplingMessage{textMsg("user", "hi")}},
			wantErr: true,
		},
		{
			name: "negative maxTokens",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params:  &mcp.CreateMessageParams{MaxTokens: -1, Messages: []*mcp.SamplingMessage{textMsg("user", "hi")}},
			wantErr: true,
		},
		{
			// Clamped, not refused: it is still only a request, and the client
			// caps it against the host's own limit.
			name: "oversized maxTokens clamps to MaxInt",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{MaxTokens: math.MaxInt64, Messages: []*mcp.SamplingMessage{textMsg("user", "hi")}},
			want: protocol.SampleRequest{
				Messages:  []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: "hi"}},
				MaxTokens: math.MaxInt,
			},
		},
		{
			name: "conversation exactly at the bound",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens:    1,
				SystemPrompt: strings.Repeat("s", 16),
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{textMsg("user", strings.Repeat("u", 16))},
			},
			want: protocol.SampleRequest{
				SystemPrompt: strings.Repeat("s", 16),
				Messages:     []protocol.SampleMessage{{Role: protocol.SampleRoleUser, Text: strings.Repeat("u", 16)}},
				MaxTokens:    1,
			},
		},
		{
			name: "conversation one byte over the bound",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens:    1,
				SystemPrompt: strings.Repeat("s", 16),
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{textMsg("user", strings.Repeat("u", 17))},
			},
			wantErr: true,
		},
		{
			name: "system prompt alone over the bound",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens:    1,
				SystemPrompt: strings.Repeat("s", 33),
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{textMsg("user", "hi")},
			},
			wantErr: true,
		},
		{
			// The bound is on the conversation, not on a message. A per-message
			// bound with no total is not a bound: a server would send more
			// messages, which is exactly what this case does.
			name: "many small messages are bounded in aggregate",
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			params: &mcp.CreateMessageParams{
				MaxTokens: 1,
				//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
				Messages: []*mcp.SamplingMessage{
					textMsg("user", strings.Repeat("a", 10)),
					textMsg("user", strings.Repeat("b", 10)),
					textMsg("user", strings.Repeat("c", 10)),
					textMsg("user", strings.Repeat("d", 10)),
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.FromSDKCreateMessageParams(tt.params, sampleBounds())
			if (err != nil) != tt.wantErr {
				t.Fatalf("FromSDKCreateMessageParams() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.SystemPrompt != tt.want.SystemPrompt || got.MaxTokens != tt.want.MaxTokens {
				t.Errorf("FromSDKCreateMessageParams() = %+v, want %+v", got, tt.want)
			}
			if len(got.Messages) != len(tt.want.Messages) {
				t.Fatalf("got %d messages, want %d", len(got.Messages), len(tt.want.Messages))
			}
			for i, m := range got.Messages {
				if m != tt.want.Messages[i] {
					t.Errorf("message %d = %+v, want %+v", i, m, tt.want.Messages[i])
				}
			}
		})
	}
}

// TestFromSDKCreateMessageParamsReportsOverLimit pins the typed error an
// over-bound conversation reports, so a caller can classify it rather than match
// on text.
func TestFromSDKCreateMessageParamsReportsOverLimit(t *testing.T) {
	t.Parallel()

	//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
	_, err := protocol.FromSDKCreateMessageParams(&mcp.CreateMessageParams{
		MaxTokens: 1,
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		Messages: []*mcp.SamplingMessage{textMsg("user", strings.Repeat("u", 33))},
	}, sampleBounds())

	var over *limits.OverLimitError
	if !errors.As(err, &over) {
		t.Fatalf("error = %v, want a *limits.OverLimitError", err)
	}
	if over.What != protocol.WhatSampleTextBytes {
		t.Errorf("What = %q, want %q", over.What, protocol.WhatSampleTextBytes)
	}
	if over.Limit != 32 {
		t.Errorf("Limit = %d, want 32", over.Limit)
	}
}

func TestToSDKCreateMessageResult(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		res     protocol.SampleResult
		wantErr bool
	}{
		{
			name: "happy path",
			res:  protocol.SampleResult{Model: "m", Text: "hello", StopReason: "endTurn"},
		},
		{
			name: "empty completion is legal",
			res:  protocol.SampleResult{Model: "m"},
		},
		{
			name:    "no model",
			res:     protocol.SampleResult{Text: "hello"},
			wantErr: true,
		},
		{
			name: "completion at the bound",
			res:  protocol.SampleResult{Model: "m", Text: strings.Repeat("x", 32)},
		},
		{
			name:    "completion over the bound",
			res:     protocol.SampleResult{Model: "m", Text: strings.Repeat("x", 33)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := protocol.ToSDKCreateMessageResult(tt.res, sampleBounds())
			if (err != nil) != tt.wantErr {
				t.Fatalf("ToSDKCreateMessageResult() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.Model != tt.res.Model {
				t.Errorf("Model = %q, want %q", got.Model, tt.res.Model)
			}
			// The role is this module's to set, never the host's: a completion
			// is an assistant turn by definition.
			if got.Role != "assistant" {
				t.Errorf("Role = %q, want %q", got.Role, "assistant")
			}
			text, ok := got.Content.(*mcp.TextContent)
			if !ok {
				t.Fatalf("Content = %T, want *mcp.TextContent", got.Content)
			}
			if text.Text != tt.res.Text {
				t.Errorf("Text = %q, want %q", text.Text, tt.res.Text)
			}
			if got.StopReason != tt.res.StopReason {
				t.Errorf("StopReason = %q, want %q", got.StopReason, tt.res.StopReason)
			}
		})
	}
}

func TestSampleRoleString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		role protocol.SampleRole
		want string
	}{
		{protocol.SampleRoleUser, "user"},
		{protocol.SampleRoleAssistant, "assistant"},
		{0, "unknown"},
		{99, "unknown"},
	}
	for _, tt := range tests {
		if got := tt.role.String(); got != tt.want {
			t.Errorf("SampleRole(%d).String() = %q, want %q", tt.role, got, tt.want)
		}
	}
}

// FuzzFromSDKCreateMessageParams drives the conversion with arbitrary
// server-supplied text. It asserts the properties the conversion promises rather
// than a value: never panic, and never retain more than the bound.
func FuzzFromSDKCreateMessageParams(f *testing.F) {
	f.Add("be brief", "user", "hello", int64(100))
	f.Add("", "assistant", strings.Repeat("x", 100), int64(1))
	f.Add(strings.Repeat("s", 40), "system", "", int64(-1))
	f.Add("\x00\xff", "user", "�", int64(math.MaxInt64))

	f.Fuzz(func(t *testing.T, system, role, text string, tokens int64) {
		b := sampleBounds()
		//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
		got, err := protocol.FromSDKCreateMessageParams(&mcp.CreateMessageParams{
			MaxTokens:    tokens,
			SystemPrompt: system,
			//lint:ignore SA1019 supported for peers ≤2025-11-25 (SEP-2577)
			Messages: []*mcp.SamplingMessage{textMsg(role, text)},
		}, b)
		if err != nil {
			return
		}
		if len(got.SystemPrompt)+len(got.Messages[0].Text) > b.MaxTextBytes {
			t.Fatalf("retained %d bytes, over bound %d", len(got.SystemPrompt)+len(got.Messages[0].Text), b.MaxTextBytes)
		}
		if got.MaxTokens <= 0 {
			t.Fatalf("MaxTokens = %d, want positive", got.MaxTokens)
		}
		if got.Messages[0].Role.String() == "unknown" {
			t.Fatalf("accepted a message with an undeclared role %q", role)
		}
	})
}
