package tamper

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/D3wier/jwt-knife/pkg/decode"
)

type Options struct {
	Claims    string
	Header    string
	Algorithm string
	Key       string
	RemoveExp bool
}

func Tamper(token string, opts Options) (string, error) {
	header, payload, _, err := decode.DecodeToMap(token)
	if err != nil {
		return "", err
	}

	if opts.Claims != "" {
		var newClaims map[string]interface{}
		if err := json.Unmarshal([]byte(opts.Claims), &newClaims); err != nil {
			return "", fmt.Errorf("invalid claims JSON: %v", err)
		}
		for k, v := range newClaims {
			payload[k] = v
		}
	}

	if opts.Header != "" {
		var newHeader map[string]interface{}
		if err := json.Unmarshal([]byte(opts.Header), &newHeader); err != nil {
			return "", fmt.Errorf("invalid header JSON: %v", err)
		}
		for k, v := range newHeader {
			header[k] = v
		}
	}

	if opts.Algorithm != "" {
		header["alg"] = opts.Algorithm
	}

	if opts.RemoveExp {
		delete(payload, "exp")
	}

	return buildToken(header, payload, opts)
}

func Forge(opts Options) (string, error) {
	header := map[string]interface{}{
		"alg": opts.Algorithm,
		"typ": "JWT",
	}

	if opts.Header != "" {
		var customHeader map[string]interface{}
		if err := json.Unmarshal([]byte(opts.Header), &customHeader); err != nil {
			return "", fmt.Errorf("invalid header JSON: %v", err)
		}
		for k, v := range customHeader {
			header[k] = v
		}
	}

	payload := make(map[string]interface{})
	if opts.Claims != "" {
		if err := json.Unmarshal([]byte(opts.Claims), &payload); err != nil {
			return "", fmt.Errorf("invalid claims JSON: %v", err)
		}
	}

	return buildToken(header, payload, opts)
}

func buildToken(header, payload map[string]interface{}, opts Options) (string, error) {
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signingInput := headerB64 + "." + payloadB64

	alg, _ := header["alg"].(string)
	alg = strings.ToLower(alg)

	if alg == "none" || alg == "" {
		return signingInput + ".", nil
	}

	key := []byte(opts.Key)
	if opts.Key != "" {
		if fileContent, err := os.ReadFile(opts.Key); err == nil {
			key = fileContent
		}
	}

	var sig []byte
	switch strings.ToUpper(alg) {
	case "HS256":
		sig = signHMAC(sha256.New, key, signingInput)
	case "HS384":
		sig = signHMAC(sha512.New384, key, signingInput)
	case "HS512":
		sig = signHMAC(sha512.New, key, signingInput)
	default:
		sig = signHMAC(sha256.New, key, signingInput)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return signingInput + "." + sigB64, nil
}

func signHMAC(hashFunc func() hash.Hash, key []byte, input string) []byte {
	mac := hmac.New(hashFunc, key)
	mac.Write([]byte(input))
	return mac.Sum(nil)
}
