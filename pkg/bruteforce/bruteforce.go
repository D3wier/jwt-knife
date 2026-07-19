package bruteforce

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

type Options struct {
	Wordlist string
	Pattern  string
	Threads  int
	Common   bool
}

var commonSecrets = []string{
	"secret", "password", "123456", "admin", "key", "test",
	"jwt_secret", "jwt-secret", "token", "auth", "apikey",
	"supersecret", "changeme", "default", "private", "public",
	"mysecret", "mykey", "secret123", "password123", "letmein",
	"1234567890", "qwerty", "abc123", "passw0rd", "hunter2",
	"kubernetes", "docker", "redis", "postgres", "mysql",
	"your-256-bit-secret", "your_secret_key", "secretkey",
	"JWT_SECRET", "APP_SECRET", "SESSION_SECRET", "TOKEN_SECRET",
	"HS256-secret", "hmac-secret", "signing-key", "auth-secret",
}

func Crack(token string, opts Options) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid JWT")
	}

	signingInput := parts[0] + "." + parts[1]
	targetSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("invalid signature encoding")
	}

	var candidates []string

	if opts.Common {
		candidates = append(candidates, commonSecrets...)
	}

	if opts.Wordlist != "" {
		f, err := os.Open(opts.Wordlist)
		if err != nil {
			return "", fmt.Errorf("cannot open wordlist: %v", err)
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			candidates = append(candidates, scanner.Text())
		}
	}

	if len(candidates) == 0 {
		candidates = commonSecrets
	}

	fmt.Printf("[*] Testing %d candidates with %d threads...\n", len(candidates), opts.Threads)

	var found atomic.Value
	var tested atomic.Int64
	var wg sync.WaitGroup
	ch := make(chan string, opts.Threads*2)

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for secret := range ch {
				if found.Load() != nil {
					return
				}
				mac := hmac.New(sha256.New, []byte(secret))
				mac.Write([]byte(signingInput))
				sig := mac.Sum(nil)

				if hmac.Equal(sig, targetSig) {
					found.Store(secret)
					return
				}
				tested.Add(1)
			}
		}()
	}

	for _, c := range candidates {
		if found.Load() != nil {
			break
		}
		ch <- c
	}
	close(ch)
	wg.Wait()

	fmt.Printf("[*] Tested %d secrets\n", tested.Load())

	if result := found.Load(); result != nil {
		return result.(string), nil
	}

	return "", fmt.Errorf("secret not found in %d candidates", len(candidates))
}
