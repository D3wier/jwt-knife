package decode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func Decode(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	header, err := decodeSegment(parts[0])
	if err != nil {
		return "", fmt.Errorf("invalid header: %v", err)
	}

	payload, err := decodeSegment(parts[1])
	if err != nil {
		return "", fmt.Errorf("invalid payload: %v", err)
	}

	headerJSON := prettyJSON(header)
	payloadJSON := prettyJSON(payload)

	var payloadMap map[string]interface{}
	json.Unmarshal(payload, &payloadMap)

	expInfo := ""
	if exp, ok := payloadMap["exp"]; ok {
		if expFloat, ok := exp.(float64); ok {
			expTime := time.Unix(int64(expFloat), 0)
			if time.Now().After(expTime) {
				expInfo = fmt.Sprintf("\n  ⚠ EXPIRED: %s", expTime.UTC().Format(time.RFC3339))
			} else {
				expInfo = fmt.Sprintf("\n  ✓ Valid until: %s", expTime.UTC().Format(time.RFC3339))
			}
		}
	}

	iatInfo := ""
	if iat, ok := payloadMap["iat"]; ok {
		if iatFloat, ok := iat.(float64); ok {
			iatTime := time.Unix(int64(iatFloat), 0)
			iatInfo = fmt.Sprintf("\n  Issued: %s", iatTime.UTC().Format(time.RFC3339))
		}
	}

	sigLen := len(parts[2])
	sigInfo := "PRESENT"
	if sigLen == 0 {
		sigInfo = "EMPTY (unsigned)"
	}

	return fmt.Sprintf(`Header:
%s

Payload:
%s%s%s

Signature: %s (%d chars)`, headerJSON, payloadJSON, expInfo, iatInfo, sigInfo, sigLen), nil
}

func DecodeToMap(token string) (header map[string]interface{}, payload map[string]interface{}, sig string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, "", fmt.Errorf("invalid JWT")
	}

	headerBytes, err := decodeSegment(parts[0])
	if err != nil {
		return nil, nil, "", err
	}
	json.Unmarshal(headerBytes, &header)

	payloadBytes, err := decodeSegment(parts[1])
	if err != nil {
		return nil, nil, "", err
	}
	json.Unmarshal(payloadBytes, &payload)

	return header, payload, parts[2], nil
}

func decodeSegment(seg string) ([]byte, error) {
	switch len(seg) % 4 {
	case 2:
		seg += "=="
	case 3:
		seg += "="
	}
	return base64.URLEncoding.DecodeString(seg)
}

func prettyJSON(data []byte) string {
	var obj interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return string(data)
	}
	pretty, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return string(data)
	}
	return string(pretty)
}
