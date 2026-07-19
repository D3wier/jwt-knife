# jwt-knife

All-in-one JWT security testing tool. Decode, tamper, brute-force, and forge JSON Web Tokens from the command line. Single binary, no dependencies.

## Features

- **Decode** — Pretty-print JWT header and payload with signature validation
- **Tamper** — Modify claims, change algorithm, strip signature
- **Algorithm attacks** — `alg:none`, RS256→HS256 key confusion, JWKS injection
- **Brute-force** — Crack weak HMAC secrets with wordlist or pattern
- **Forge** — Generate new tokens with custom claims and signing
- **Pipeline-friendly** — Reads from stdin, outputs clean tokens

## Installation

```bash
go install github.com/D3wier/jwt-knife/cmd/jwt-knife@latest
```

Or download a binary from [Releases](https://github.com/D3wier/jwt-knife/releases).

## Usage

```bash
# Decode a JWT
jwt-knife decode eyJhbGciOiJIUzI1NiJ9...

# Decode from clipboard/stdin
echo $TOKEN | jwt-knife decode

# Tamper claims
jwt-knife tamper -t $TOKEN -c '{"role":"admin","sub":"1"}'

# Algorithm none attack
jwt-knife tamper -t $TOKEN --alg none

# RS256 to HS256 key confusion
jwt-knife tamper -t $TOKEN --alg HS256 --key public.pem

# Brute-force HMAC secret
jwt-knife crack -t $TOKEN -w wordlist.txt

# Brute-force with pattern
jwt-knife crack -t $TOKEN --pattern '[a-z]{6}'

# Forge a new token
jwt-knife forge -c '{"sub":"1","role":"admin"}' --key secret123

# Forge with custom header
jwt-knife forge -c '{"sub":"1"}' -H '{"kid":"../../dev/null"}' --key ''
```

## Commands

### `decode`
```bash
jwt-knife decode <token>
jwt-knife decode -t <token>
echo <token> | jwt-knife decode
```

Output:
```
Header:
{
  "alg": "HS256",
  "typ": "JWT"
}

Payload:
{
  "sub": "1234567890",
  "name": "John Doe",
  "iat": 1516239022,
  "exp": 1516242622   ← EXPIRED (2024-01-17 15:30:22 UTC)
}

Signature: VALID (if key provided) / NOT VERIFIED
```

### `tamper`
```bash
# Change claims
jwt-knife tamper -t $TOKEN -c '{"role":"admin"}'

# Algorithm none (remove signature)
jwt-knife tamper -t $TOKEN --alg none

# Key confusion attack
jwt-knife tamper -t $TOKEN --alg HS256 --key public.pem

# Add/modify header
jwt-knife tamper -t $TOKEN -H '{"kid":"/dev/null"}'

# Remove expiration
jwt-knife tamper -t $TOKEN --remove-exp
```

### `crack`
```bash
# Wordlist attack
jwt-knife crack -t $TOKEN -w /usr/share/wordlists/rockyou.txt

# With threads
jwt-knife crack -t $TOKEN -w wordlist.txt --threads 20

# Pattern brute-force (short secrets)
jwt-knife crack -t $TOKEN --pattern '[a-z0-9]{1,6}'

# Common secrets (built-in list)
jwt-knife crack -t $TOKEN --common
```

### `forge`
```bash
# Create token with secret
jwt-knife forge -c '{"sub":"admin","role":"superuser"}' --key mysecret

# Create with RSA key
jwt-knife forge -c '{"sub":"1"}' --alg RS256 --key private.pem

# Specify expiration
jwt-knife forge -c '{"sub":"1"}' --key secret --exp 1h

# No signature
jwt-knife forge -c '{"sub":"1"}' --alg none
```

## Flags Reference

| Flag | Commands | Description |
|------|----------|-------------|
| `-t` | all | Input token |
| `-c` | tamper, forge | Claims JSON to set/merge |
| `-H` | tamper, forge | Header JSON to set/merge |
| `--alg` | tamper, forge | Set algorithm (none, HS256, RS256, etc.) |
| `--key` | tamper, crack, forge | Signing key or key file |
| `-w` | crack | Wordlist path |
| `--threads` | crack | Concurrency (default: 10) |
| `--pattern` | crack | Brute-force pattern |
| `--common` | crack | Try built-in common secrets |
| `--exp` | forge | Expiration (1h, 24h, 7d) |
| `--remove-exp` | tamper | Remove exp claim |
| `-o` | all | Output format (token, json, full) |

## Security Testing Checklist

1. **alg:none** — Does the server accept unsigned tokens?
2. **Key confusion** — RS256→HS256 with public key as secret?
3. **Weak secret** — Can the HMAC secret be cracked?
4. **Claim tampering** — Is `role`/`admin`/`sub` validated server-side?
5. **Expired tokens** — Does the server enforce `exp`?
6. **kid injection** — Can `kid` header be used for path traversal/SQLi?
7. **JKU/X5U** — Can header point to attacker-controlled key server?
8. **Missing signature validation** — Accept any signature?

## License

MIT License — see [LICENSE](LICENSE)
