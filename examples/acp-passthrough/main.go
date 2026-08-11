package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"

	"github.com/looprig/mcp/pkg/collab"
)

func main() {
	output, err := runExample()
	must(err)
	fmt.Print(output)
}

func runExample() (string, error) {
	capability := bytes.Repeat([]byte{0x2a}, collab.CapabilityBytes)
	clientConn, brokerConn := net.Pipe()
	defer brokerConn.Close()
	dialed := false
	c, err := collab.NewClientWithDialer(collab.ClientConfig{Endpoint: "/tmp/docs-broker.sock", Capability: capability}, func(context.Context, string) (net.Conn, error) {
		dialed = true
		return clientConn, nil
	})
	if err != nil {
		return "", err
	}

	_, invalidErr := c.MessageAgent(context.Background(), collab.MessageAgentRequest{
		AgentID: "not-a-uuid",
		Message: "This must be rejected locally.",
	})
	invalidRejectedBeforeDial := invalidErr != nil && !dialed

	brokerDone := make(chan error, 1)
	go func() {
		gotCapability, err := collab.ReadHandshake(brokerConn)
		if err != nil || !bytes.Equal(gotCapability, capability) {
			brokerDone <- fmt.Errorf("authenticate broker: %w", err)
			return
		}
		request, err := collab.ReadFrame(brokerConn)
		if err != nil {
			brokerDone <- err
			return
		}
		var call collab.MessageAgentRequest
		if err := json.Unmarshal(request, &call); err != nil {
			brokerDone <- err
			return
		}
		response, _ := json.Marshal(collab.DelegateResult{AgentID: call.AgentID, Name: "reviewer", State: "idle", DeliveryStatus: "delivered", ResponseStatus: "completed", Response: "review complete"})
		brokerDone <- collab.WriteFrame(brokerConn, response)
	}()

	result, err := c.MessageAgent(context.Background(), collab.MessageAgentRequest{
		AgentID:         "11111111-1111-4111-8111-111111111111",
		Message:         "Review this change.",
		WaitForResponse: true,
	})
	if err != nil {
		return "", err
	}
	if err := <-brokerDone; err != nil {
		return "", err
	}
	return fmt.Sprintf("invalid-rejected-before-dial=%t\ndelivery=%s\nresponse=%s\n", invalidRejectedBeforeDial, result.DeliveryStatus, result.Response), nil
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
