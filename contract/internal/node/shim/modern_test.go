package shim

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Telara-Labs/hilo/contract/internal/node/daemon"
)

func TestStatelessLocalAnswersWithoutDaemon(t *testing.T) {
	for _, v := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2026-07-28"} {
		for _, method := range []string{"server/discover", "tools/list", "ping"} {
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":9007199254740993,"method":%q,"params":{"_meta":{"io.modelcontextprotocol/protocolVersion":%q,"io.modelcontextprotocol/clientCapabilities":{},"com.telara/conversation":"offline-chat","progressToken":"p","example.com/trace-id":"t"}}}`+"\n", method, v)
			starts := 0
			var output bytes.Buffer
			cfg := Config{Start: func() error { starts++; return errors.New("unexpected startup") }}
			if e := Run(context.Background(), strings.NewReader(input), &output, cfg); e != nil {
				t.Fatal(e)
			}
			var out daemon.Response
			if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &out) != nil || out.Error != nil || string(out.ID) != "9007199254740993" || starts != 0 {
				t.Fatal("offline protocol/correlation failed")
			}
			if out.Result.(map[string]any)["resultType"] != "complete" {
				t.Fatal("missing modern result type")
			}
		}
	}
	for _, method := range []string{"server/discover", "tools/list", "ping"} {
		input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"_meta":{"com.telara/conversation":42,"example.com/trace-id":"t"}}}`+"\n", method)
		var output bytes.Buffer
		if e := Run(context.Background(), strings.NewReader(input), &output, Config{Start: func() error { t.Error("invalid identity triggered startup"); return errors.New("unexpected startup") }}); e != nil {
			t.Fatal(e)
		}
		var out daemon.Response
		_ = json.Unmarshal(bytes.TrimSpace(output.Bytes()), &out)
		if out.Error == nil || out.Error.Code != -32602 {
			t.Fatal("invalid identity accepted")
		}
	}
}

func TestMalformedModernMetadataRejectedWithoutDaemonStartup(t *testing.T) {
	for _, meta := range []string{
		`{"io.modelcontextprotocol/clientCapabilities":{}}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":null}`,
		`{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":42}`,
	} {
		for _, method := range []string{"server/discover", "tools/list", "tools/call", "ping"} {
			input := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"_meta":%s}}`+"\n", method, meta)
			var output bytes.Buffer
			starts := 0
			if err := Run(context.Background(), strings.NewReader(input), &output, Config{Start: func() error { starts++; return errors.New("unexpected startup") }}); err != nil {
				t.Fatal(err)
			}
			var response daemon.Response
			if json.Unmarshal(bytes.TrimSpace(output.Bytes()), &response) != nil || response.Error == nil || response.Error.Code != -32602 || response.Error.Message != "invalid_protocol_metadata" || starts != 0 {
				t.Fatal("malformed metadata escaped offline shim validation", output.String())
			}
		}
	}
}
