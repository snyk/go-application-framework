package extension

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func testTypeID(t *testing.T) workflow.Identifier {
	t.Helper()
	return workflow.NewTypeIdentifier(workflow.NewWorkflowIdentifier("hello"), "result")
}

func TestEncodeDecodePayload_RoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		payload  interface{}
		encoding extensionpb.PayloadEncoding
		want     interface{}
	}{
		{"nil", nil, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED, nil},
		{"bytes", []byte("hello"), extensionpb.PayloadEncoding_PAYLOAD_ENCODING_BYTES, []byte("hello")},
		{"string", "hello", extensionpb.PayloadEncoding_PAYLOAD_ENCODING_STRING, "hello"},
		{"json", map[string]interface{}{"a": "b"}, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_JSON, map[string]interface{}{"a": "b"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, enc, err := encodePayload(tc.payload)
			require.NoError(t, err)
			assert.Equal(t, tc.encoding, enc)

			got, err := decodePayload(b, enc)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDataToMsgToData_RoundTrip(t *testing.T) {
	id := testTypeID(t)
	original := workflow.NewData(id, "application/json", []byte(`{"ok":true}`))
	original.SetContentLocation("/tmp/result.json")

	msg, err := dataToMsg(original)
	require.NoError(t, err)
	assert.Equal(t, "application/json", msg.GetMetadata()[workflow.Content_type_key])
	assert.Equal(t, "/tmp/result.json", msg.GetMetadata()[workflow.Content_location_key])
	assert.Equal(t, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_BYTES, msg.GetPayloadEncoding())

	roundTripped, err := msgToData(msg, nil)
	require.NoError(t, err)

	assert.Equal(t, "application/json", roundTripped.GetContentType())
	assert.Equal(t, "/tmp/result.json", roundTripped.GetContentLocation())
	assert.Equal(t, []byte(`{"ok":true}`), roundTripped.GetPayload())
	// Scheme/host/path are preserved. The fragment is an internal correlation id
	// that workflow.NewData regenerates on construction, so it is not stable
	// across the boundary by design.
	got := roundTripped.GetIdentifier()
	assert.Equal(t, "did", got.Scheme)
	assert.Equal(t, id.Host, got.Host)
	assert.Equal(t, "/result", got.Path)
}

func TestDataSliceRoundTrip(t *testing.T) {
	id := testTypeID(t)
	input := []workflow.Data{
		workflow.NewData(id, "text/plain", []byte("one")),
		workflow.NewData(id, "text/plain", []byte("two")),
	}

	msgs, err := dataSliceToMsgs(input)
	require.NoError(t, err)
	require.Len(t, msgs, 2)

	output, err := msgsToDataSlice(msgs, nil)
	require.NoError(t, err)
	require.Len(t, output, 2)
	assert.Equal(t, []byte("one"), output[0].GetPayload())
	assert.Equal(t, []byte("two"), output[1].GetPayload())
}

func TestMsgToData_InvalidIdentifier(t *testing.T) {
	_, err := msgToData(&extensionpb.DataMsg{Identifier: "://bad"}, nil)
	assert.Error(t, err)
}
