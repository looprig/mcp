package collab

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMessageAgentValidationDefaultsAndBoundsBeforeIPC(t *testing.T) {
	t.Parallel()

	validID := "55555555-5555-4555-8555-555555555555"
	tests := []struct {
		name      string
		input     string
		wantWait  bool
		wantLimit *int
		wantErr   bool
	}{
		{name: "omitted wait defaults true", input: `{"agent_id":"` + validID + `","message":"hello"}`, wantWait: true},
		{name: "explicit false remains false", input: `{"agent_id":"` + validID + `","message":"hello","wait_for_response":false}`, wantWait: false},
		{name: "omitted timeout remains absent", input: `{"agent_id":"` + validID + `","message":"hello"}`, wantWait: true},
		{name: "zero timeout accepted", input: `{"agent_id":"` + validID + `","message":"hello","timeout_seconds":0}`, wantWait: true, wantLimit: intPtr(0)},
		{name: "exact maximum accepted", input: `{"agent_id":"` + validID + `","message":"hello","timeout_seconds":86400}`, wantWait: true, wantLimit: intPtr(86400)},
		{name: "negative timeout rejected", input: `{"agent_id":"` + validID + `","message":"hello","timeout_seconds":-1}`, wantErr: true},
		{name: "above maximum rejected", input: `{"agent_id":"` + validID + `","message":"hello","timeout_seconds":86401}`, wantErr: true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := DecodeMessageAgent([]byte(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("DecodeMessageAgent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.WaitForResponse != tt.wantWait {
				t.Fatalf("WaitForResponse = %v, want %v", got.WaitForResponse, tt.wantWait)
			}
			if (got.TimeoutSeconds == nil) != (tt.wantLimit == nil) {
				t.Fatalf("TimeoutSeconds = %v, want %v", got.TimeoutSeconds, tt.wantLimit)
			}
			if got.TimeoutSeconds != nil && *got.TimeoutSeconds != *tt.wantLimit {
				t.Fatalf("TimeoutSeconds = %d, want %d", *got.TimeoutSeconds, *tt.wantLimit)
			}
		})
	}
}

func TestMessageAgentValidationRejectsIdentityAndCorrelationFields(t *testing.T) {
	t.Parallel()

	base := `{"agent_id":"55555555-5555-4555-8555-555555555555","message":"hello"}`
	for _, field := range []string{"session_id", "origin_loop_id", "request_id", "parent_tool_use_id", "correlation_id"} {
		t.Run(field, func(t *testing.T) {
			input := strings.TrimSuffix(base, "}") + `,"` + field + `":"forged"}`
			if _, err := DecodeMessageAgent([]byte(input)); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("DecodeMessageAgent() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestMessageAgentValidationRejectsMalformedAndOversizedValues(t *testing.T) {
	t.Parallel()

	validID := "55555555-5555-4555-8555-555555555555"
	tests := []string{
		`{"agent_id":"","message":"hello"}`,
		`{"agent_id":"00000000-0000-0000-0000-000000000000","message":"hello"}`,
		`{"agent_id":"not-a-uuid","message":"hello"}`,
		`{"agent_id":"` + validID + `","message":"   "}`,
		`{"agent_id":"` + validID + `","message":null}`,
		`{"agent_id":"` + validID + `","message":"hello","wait_for_response":null}`,
		`{"agent_id":"` + validID + `","message":"hello","timeout_seconds":null}`,
		`{"agent_id":"` + validID + `","message":"hello"}{}`,
	}
	for _, input := range tests {
		if _, err := DecodeMessageAgent([]byte(input)); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("DecodeMessageAgent(%q) error = %v, want ErrInvalidRequest", input, err)
		}
	}
	oversized := `{"agent_id":"` + validID + `","message":"` + strings.Repeat("x", MaxMessageBytes+1) + `"}`
	if _, err := DecodeMessageAgent([]byte(oversized)); !errors.Is(err, ErrInputLimit) {
		t.Fatalf("oversized message error = %v, want ErrInputLimit", err)
	}
}

func TestCapabilityTokenEncodingRequiresExactly32Bytes(t *testing.T) {
	t.Parallel()

	capability := bytes.Repeat([]byte{0xab}, CapabilityBytes)
	encoded := hex.EncodeToString(capability)
	got, err := DecodeCapabilityToken(encoded)
	if err != nil {
		t.Fatalf("DecodeCapabilityToken() error = %v", err)
	}
	if !bytes.Equal(got, capability) {
		t.Fatalf("decoded capability = %x, want %x", got, capability)
	}
	for _, value := range []string{"", "00", strings.Repeat("0", 62), strings.Repeat("0", 66), strings.Repeat("z", 64)} {
		if _, err := DecodeCapabilityToken(value); !errors.Is(err, ErrInvalidCapability) {
			t.Errorf("DecodeCapabilityToken(%q) error = %v, want ErrInvalidCapability", value, err)
		}
	}
}

func TestHandshakeAndFramesAreLengthBounded(t *testing.T) {
	t.Parallel()

	capability := bytes.Repeat([]byte{0x11}, CapabilityBytes)
	var wire bytes.Buffer
	if err := WriteHandshake(&wire, capability); err != nil {
		t.Fatalf("WriteHandshake() error = %v", err)
	}
	if got := binary.BigEndian.Uint32(wire.Bytes()[:4]); got != CapabilityBytes {
		t.Fatalf("handshake length = %d, want %d", got, CapabilityBytes)
	}
	if got := wire.Len(); got != 4+CapabilityBytes {
		t.Fatalf("handshake bytes = %d, want %d", got, 4+CapabilityBytes)
	}
	got, err := ReadHandshake(&wire)
	if err != nil {
		t.Fatalf("ReadHandshake() error = %v", err)
	}
	if !bytes.Equal(got, capability) {
		t.Fatalf("ReadHandshake() = %x, want %x", got, capability)
	}
	if err := WriteFrame(&wire, []byte(`{"ok":true}`)); err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	frame, err := ReadFrame(&wire)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if string(frame) != `{"ok":true}` {
		t.Fatalf("ReadFrame() = %q", frame)
	}
	if err := WriteFrame(&wire, bytes.Repeat([]byte{'x'}, MaxFrameBytes+1)); !errors.Is(err, ErrFrameLimit) {
		t.Fatalf("oversized WriteFrame() error = %v, want ErrFrameLimit", err)
	}
}

func TestUnixClientAuthenticatesFramesAndObservesResponse(t *testing.T) {
	if !supportsUnixSockets() {
		t.Skip("Unix socket test")
	}
	t.Parallel()

	endpoint := filepath.Join("/private/tmp", fmt.Sprintf("coderig-collab-%d.sock", os.Getpid()))
	_ = os.Remove(endpoint)
	t.Cleanup(func() { _ = os.Remove(endpoint) })
	listener, err := net.Listen("unix", endpoint)
	if err != nil {
		t.Skipf("Unix socket unavailable in this sandbox: %v", err)
	}
	defer listener.Close()
	capability := bytes.Repeat([]byte{0x22}, CapabilityBytes)
	requestSeen := make(chan MessageAgentRequest, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer conn.Close()
		gotCapability, readErr := ReadHandshake(conn)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		if !bytes.Equal(gotCapability, capability) {
			serverErr <- ErrAuthentication
			return
		}
		frame, readErr := ReadFrame(conn)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		request, decodeErr := DecodeMessageAgent(frame)
		if decodeErr != nil {
			serverErr <- decodeErr
			return
		}
		requestSeen <- request
		serverErr <- WriteFrame(conn, []byte(`{"agent_id":"55555555-5555-4555-8555-555555555555","name":"worker","state":"idle","delivery_status":"queued","response_status":"completed","response":"done"}`))
	}()

	client, err := NewClient(ClientConfig{Endpoint: endpoint, Capability: capability, ConnectTimeout: time.Second, AdmissionTimeout: time.Second})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	result, err := client.Call(context.Background(), MessageAgentRequest{AgentID: "55555555-5555-4555-8555-555555555555", Message: "hello", WaitForResponse: true})
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if result.Response != "done" || result.DeliveryStatus != "queued" {
		t.Fatalf("result = %#v, want queued done", result)
	}
	select {
	case request := <-requestSeen:
		if !request.WaitForResponse || request.Message != "hello" {
			t.Fatalf("request = %#v", request)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not observe request")
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server error = %v", err)
	}
}

func TestClientValidatesBeforeDial(t *testing.T) {
	t.Parallel()

	var dialed bool
	client, err := NewClientWithDialer(ClientConfig{Endpoint: "/unused", Capability: bytes.Repeat([]byte{1}, CapabilityBytes)}, func(context.Context, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("dialed")
	})
	if err != nil {
		t.Fatalf("NewClientWithDialer() error = %v", err)
	}
	_, err = client.Call(context.Background(), MessageAgentRequest{AgentID: "bad", Message: "hello", WaitForResponse: true})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("Call() error = %v, want ErrInvalidRequest", err)
	}
	if dialed {
		t.Fatal("invalid request dialed the broker")
	}
}

func TestClientResponseAndTransportFailuresDoNotExposeSecrets(t *testing.T) {
	t.Parallel()

	secret := "secret-capability-marker"
	client, err := NewClientWithDialer(ClientConfig{Endpoint: "/path/" + secret, Capability: bytes.Repeat([]byte{1}, CapabilityBytes)}, func(context.Context, string) (net.Conn, error) {
		return nil, errors.New(secret)
	})
	if err != nil {
		t.Fatalf("NewClientWithDialer() error = %v", err)
	}
	_, err = client.Call(context.Background(), MessageAgentRequest{AgentID: "55555555-5555-4555-8555-555555555555", Message: "hello", WaitForResponse: true})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("Call() error = %v, want redacted transport failure", err)
	}
}

func TestCollabMCPIntegrationClientConfigAndWireProjection(t *testing.T) {
	t.Parallel()
	secretMarker := "wire-secret-marker"
	capability := bytes.Repeat([]byte{0x44}, CapabilityBytes)
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	client, err := NewClientWithDialer(ClientConfig{Endpoint: "/tmp/" + secretMarker, Token: capability}, func(context.Context, string) (net.Conn, error) {
		return clientConn, nil
	})
	if err != nil {
		t.Fatalf("NewClientWithDialer: %v", err)
	}
	cfg := client.Config()
	if cfg.Token != nil {
		t.Fatalf("Config retained token bytes: %x", cfg.Token)
	}
	if !bytes.Equal(cfg.Capability, capability) || cfg.Endpoint != "/tmp/"+secretMarker {
		t.Fatalf("Config projection = %#v, want endpoint and capability without token", cfg)
	}
	if cfg.ConnectTimeout <= 0 || cfg.AdmissionTimeout <= 0 || cfg.MaxFrameBytes != MaxFrameBytes {
		t.Fatalf("normalized Config = %#v, want positive defaults and max frame %d", cfg, MaxFrameBytes)
	}

	serverDone := make(chan error, 1)
	go func() {
		gotCapability, err := ReadHandshake(serverConn)
		if err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(gotCapability, capability) {
			serverDone <- ErrAuthentication
			return
		}
		frame, err := ReadFrame(serverConn)
		if err != nil {
			serverDone <- err
			return
		}
		if bytes.Contains(frame, []byte(secretMarker)) || bytes.Contains(frame, []byte(hex.EncodeToString(capability))) {
			serverDone <- errors.New("configuration secret appeared in request JSON")
			return
		}
		serverDone <- WriteFrame(serverConn, []byte(`{"agent_id":"55555555-5555-4555-8555-555555555555","name":"child","state":"idle","delivery_status":"injected","response_status":"completed","response":"round trip"}`))
	}()
	result, err := client.Call(context.Background(), MessageAgentRequest{AgentID: "55555555-5555-4555-8555-555555555555", Message: "hello", WaitForResponse: true})
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if result.Response != "round trip" || result.DeliveryStatus != "injected" || result.ResponseStatus != "completed" {
		t.Fatalf("DelegateResult = %#v, want public round-trip fields", result)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("fake broker: %v", err)
	}
}

func TestClientSupportsAdmissionDeadlineWithoutBoundingResponseObservation(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()
	capability := bytes.Repeat([]byte{0x33}, CapabilityBytes)
	serverReady := make(chan struct{})
	go func() {
		defer serverConn.Close()
		close(serverReady)
		if _, err := ReadHandshake(serverConn); err != nil {
			return
		}
		if _, err := ReadFrame(serverConn); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_ = WriteFrame(serverConn, []byte(`{"agent_id":"55555555-5555-4555-8555-555555555555","name":"worker","state":"idle","delivery_status":"injected","response_status":"completed","response":"late"}`))
	}()
	<-serverReady
	client, err := NewClientWithDialer(ClientConfig{Endpoint: "/unused", Capability: capability, AdmissionTimeout: 10 * time.Millisecond}, func(context.Context, string) (net.Conn, error) {
		return clientConn, nil
	})
	if err != nil {
		t.Fatalf("NewClientWithDialer() error = %v", err)
	}
	result, err := client.Call(context.Background(), MessageAgentRequest{AgentID: "55555555-5555-4555-8555-555555555555", Message: "hello", WaitForResponse: true})
	if err != nil {
		t.Fatalf("Call() error = %v, want response after admission deadline", err)
	}
	if result.Response != "late" {
		t.Fatalf("Response = %q, want late", result.Response)
	}
}

func TestEnvironmentConfigRejectsMissingOrInvalidCapability(t *testing.T) {
	t.Parallel()

	for _, env := range []map[string]string{
		{},
		{EndpointEnv: "/tmp/broker"},
		{TokenEnv: hex.EncodeToString(bytes.Repeat([]byte{1}, CapabilityBytes))},
		{EndpointEnv: "/tmp/broker", TokenEnv: "bad"},
	} {
		if _, err := ConfigFromEnv(func(name string) (string, bool) { value, ok := env[name]; return value, ok }); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("ConfigFromEnv(%v) error = %v, want ErrInvalidConfig", env, err)
		}
	}
}

func FuzzDecodeMessageAgentNeverPanics(f *testing.F) {
	f.Add([]byte(`{"agent_id":"55555555-5555-4555-8555-555555555555","message":"hello"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte{0xff, 0xfe, 0xfd})
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = DecodeMessageAgent(input)
	})
}

func intPtr(value int) *int { return &value }

func supportsUnixSockets() bool { return os.PathSeparator == '/' }
