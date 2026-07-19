package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/D3wier/jwt-knife/pkg/bruteforce"
	"github.com/D3wier/jwt-knife/pkg/decode"
	"github.com/D3wier/jwt-knife/pkg/tamper"
)

var banner = `
     ___  _    _  _____        _  __      _  __
    |_  || |  | ||_   _|      | |/ /     (_)/ _|
      | || |  | |  | |  ______| ' / _ __  _| |_ ___
      | || |/\| |  | | |______|  < | '_ \| |  _/ _ \
  /\__/ /\  /\  /  | |        | . \| | | | | ||  __/
  \____/  \/  \/   \_/        |_|\_\_| |_|_|_| \___|
`

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "decode":
		cmdDecode(args)
	case "tamper":
		cmdTamper(args)
	case "crack":
		cmdCrack(args)
	case "forge":
		cmdForge(args)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func getToken(args []string) string {
	for i, a := range args {
		if a == "-t" && i+1 < len(args) {
			return args[i+1]
		}
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0]
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			return strings.TrimSpace(scanner.Text())
		}
	}
	return ""
}

func getFlag(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func cmdDecode(args []string) {
	token := getToken(args)
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: no token provided")
		os.Exit(1)
	}

	fmt.Print(banner)
	result, err := decode.Decode(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result)
}

func cmdTamper(args []string) {
	token := getToken(args)
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: no token provided")
		os.Exit(1)
	}

	opts := tamper.Options{
		Claims:    getFlag(args, "-c"),
		Header:    getFlag(args, "-H"),
		Algorithm: getFlag(args, "--alg"),
		Key:       getFlag(args, "--key"),
		RemoveExp: hasFlag(args, "--remove-exp"),
	}

	result, err := tamper.Tamper(token, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result)
}

func cmdCrack(args []string) {
	token := getToken(args)
	if token == "" {
		fmt.Fprintln(os.Stderr, "Error: no token provided")
		os.Exit(1)
	}

	fmt.Print(banner)

	opts := bruteforce.Options{
		Wordlist: getFlag(args, "-w"),
		Pattern:  getFlag(args, "--pattern"),
		Threads:  10,
		Common:   hasFlag(args, "--common"),
	}

	if t := getFlag(args, "--threads"); t != "" {
		fmt.Sscanf(t, "%d", &opts.Threads)
	}

	secret, err := bruteforce.Crack(token, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Secret found: %s\n", secret)
}

func cmdForge(args []string) {
	opts := tamper.Options{
		Claims:    getFlag(args, "-c"),
		Header:    getFlag(args, "-H"),
		Algorithm: getFlag(args, "--alg"),
		Key:       getFlag(args, "--key"),
	}

	if opts.Algorithm == "" {
		opts.Algorithm = "HS256"
	}

	result, err := tamper.Forge(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(result)
}

func printUsage() {
	fmt.Print(banner)
	fmt.Println(`
Usage: jwt-knife <command> [options]

Commands:
  decode    Decode and inspect a JWT
  tamper    Modify token claims/headers
  crack     Brute-force HMAC secret
  forge     Create a new JWT from scratch

Examples:
  jwt-knife decode eyJhbGci...
  jwt-knife tamper -t $TOKEN -c '{"role":"admin"}'
  jwt-knife tamper -t $TOKEN --alg none
  jwt-knife crack -t $TOKEN -w wordlist.txt
  jwt-knife forge -c '{"sub":"1"}' --key secret

Use 'jwt-knife <command> --help' for more information.`)
}
