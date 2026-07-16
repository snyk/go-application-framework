package extension

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/snyk/go-application-framework/pkg/configuration"
	extensionpb "github.com/snyk/go-application-framework/pkg/extension/proto"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// The workflow.Data interface only exposes the content-type and content-location
// metadata keys (there is no way to enumerate arbitrary headers through it), so
// those are the keys that cross the process boundary. The metadata map is kept
// open so additional well-known keys can be added without a wire change.

// dataToMsg serializes a workflow.Data into its wire form.
func dataToMsg(d workflow.Data) (*extensionpb.DataMsg, error) {
	payload, encoding, err := encodePayload(d.GetPayload())
	if err != nil {
		return nil, fmt.Errorf("encoding payload for %q: %w", d.GetIdentifier(), err)
	}

	metadata := map[string]string{}
	if ct := d.GetContentType(); ct != "" {
		metadata[workflow.Content_type_key] = ct
	}
	if cl := d.GetContentLocation(); cl != "" {
		metadata[workflow.Content_location_key] = cl
	}

	return &extensionpb.DataMsg{
		Identifier:      d.GetIdentifier().String(),
		Metadata:        metadata,
		Payload:         payload,
		PayloadEncoding: encoding,
	}, nil
}

// msgToData reconstructs a workflow.Data from its wire form. config may be nil,
// in which case Data falls back to environment-backed defaults for payload
// spill-to-disk behaviour.
func msgToData(m *extensionpb.DataMsg, config configuration.Configuration) (workflow.Data, error) {
	id, err := url.Parse(m.GetIdentifier())
	if err != nil {
		return nil, fmt.Errorf("parsing data identifier %q: %w", m.GetIdentifier(), err)
	}

	payload, err := decodePayload(m.GetPayload(), m.GetPayloadEncoding())
	if err != nil {
		return nil, fmt.Errorf("decoding payload for %q: %w", m.GetIdentifier(), err)
	}

	contentType := m.GetMetadata()[workflow.Content_type_key]

	var opts []workflow.Option
	if config != nil {
		opts = append(opts, workflow.WithConfiguration(config))
	}

	data := workflow.NewData(id, contentType, payload, opts...)
	for key, value := range m.GetMetadata() {
		if key == workflow.Content_type_key {
			continue // already applied via NewData
		}
		data.SetMetaData(key, value)
	}

	return data, nil
}

func dataSliceToMsgs(data []workflow.Data) ([]*extensionpb.DataMsg, error) {
	msgs := make([]*extensionpb.DataMsg, 0, len(data))
	for _, d := range data {
		msg, err := dataToMsg(d)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}
	return msgs, nil
}

func msgsToDataSlice(msgs []*extensionpb.DataMsg, config configuration.Configuration) ([]workflow.Data, error) {
	data := make([]workflow.Data, 0, len(msgs))
	for _, m := range msgs {
		d, err := msgToData(m, config)
		if err != nil {
			return nil, err
		}
		data = append(data, d)
	}
	return data, nil
}

// encodePayload converts an arbitrary workflow payload into transportable bytes.
// []byte and string are sent verbatim; anything else is JSON-encoded.
func encodePayload(payload interface{}) ([]byte, extensionpb.PayloadEncoding, error) {
	switch v := payload.(type) {
	case nil:
		return nil, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED, nil
	case []byte:
		return v, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_BYTES, nil
	case string:
		return []byte(v), extensionpb.PayloadEncoding_PAYLOAD_ENCODING_STRING, nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return nil, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED, err
		}
		return b, extensionpb.PayloadEncoding_PAYLOAD_ENCODING_JSON, nil
	}
}

// decodePayload reverses encodePayload. JSON payloads decode into generic Go
// values (map[string]interface{}, []interface{}, etc.).
func decodePayload(payload []byte, encoding extensionpb.PayloadEncoding) (interface{}, error) {
	switch encoding {
	case extensionpb.PayloadEncoding_PAYLOAD_ENCODING_UNSPECIFIED:
		return nil, nil
	case extensionpb.PayloadEncoding_PAYLOAD_ENCODING_BYTES:
		return payload, nil
	case extensionpb.PayloadEncoding_PAYLOAD_ENCODING_STRING:
		return string(payload), nil
	case extensionpb.PayloadEncoding_PAYLOAD_ENCODING_JSON:
		var v interface{}
		if err := json.Unmarshal(payload, &v); err != nil {
			return nil, err
		}
		return v, nil
	default:
		return nil, fmt.Errorf("unknown payload encoding: %v", encoding)
	}
}
