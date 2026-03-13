package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	serverBin   string // path to compiled server binary
	goE2EBin    string // path to compiled Go E2E client binary
	swiftE2EBin string // path to compiled Swift E2E client binary
	repoRoot    string
)

func TestMain(m *testing.M) {
	root, err := filepath.Abs(filepath.Join(".."))
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot resolve repo root: %v\n", err)
		os.Exit(1)
	}
	repoRoot = root

	// Build server binary
	serverBin = filepath.Join(root, "server", "latch-relay")
	cmd := exec.Command("go", "build", "-o", serverBin, ".")
	cmd.Dir = filepath.Join(root, "server")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build server: %v\n", err)
		os.Exit(1)
	}

	// Build Go E2E client binary
	goE2EBin = filepath.Join(root, "sdk", "go", "latch-e2e")
	cmd = exec.Command("go", "build", "-o", goE2EBin, "./cmd/latch-e2e")
	cmd.Dir = filepath.Join(root, "sdk", "go")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build Go E2E client: %v\n", err)
		os.Exit(1)
	}

	// Build Swift E2E client binary
	cmd = exec.Command("swift", "build")
	cmd.Dir = filepath.Join(root, "sdk", "swift")
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to build Swift E2E client: %v (Swift tests will be skipped)\n", err)
	} else {
		// Find the built binary
		binPathCmd := exec.Command("swift", "build", "--show-bin-path")
		binPathCmd.Dir = filepath.Join(root, "sdk", "swift")
		out, err := binPathCmd.Output()
		if err == nil {
			swiftE2EBin = filepath.Join(strings.TrimSpace(string(out)), "latch-e2e")
		}
	}

	os.Exit(m.Run())
}

// getFreePort finds a random free TCP port.
func getFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port, nil
}

// startServer starts the relay server on the given port and returns a cancel function.
func startServer(t *testing.T, port int) (cancel func()) {
	t.Helper()

	ctx, cancelFn := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("PORT=%d", port),
		"MAX_PAIRINGS_PER_IP=100",
		"MAX_CHANNELS_PER_IP=100",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		cancelFn()
		t.Fatalf("start server: %v", err)
	}

	// Wait for server to be ready
	addr := fmt.Sprintf("http://127.0.0.1:%d/healthz", port)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(addr)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	return func() {
		cancelFn()
		cmd.Wait()
	}
}

// clientResult holds the output of a CLI client run.
type clientResult struct {
	ReceivedFrom string
	ReceivedData string // decoded message text
	Stderr       string
	Err          error
}

// runGoClient runs the Go E2E client and returns the result.
func runGoClient(ctx context.Context, serverURL, id, code, sendMsg string) clientResult {
	return runCLI(ctx, goE2EBin, []string{
		"-server", serverURL,
		"-id", id,
		"-code", code,
		"-send", sendMsg,
	}, "", nil)
}

// runPythonClient runs the Python E2E client and returns the result.
func runPythonClient(ctx context.Context, serverURL, id, code, sendMsg string) clientResult {
	scriptPath := filepath.Join(repoRoot, "sdk", "python", "e2e_client.py")
	return runCLI(ctx, "python3", []string{
		scriptPath,
		"--server", serverURL,
		"--id", id,
		"--code", code,
		"--send", sendMsg,
	}, filepath.Join(repoRoot, "sdk", "python"), nil)
}

// runNodeClient runs the Node.js E2E client and returns the result.
func runNodeClient(ctx context.Context, serverURL, id, code, sendMsg string) clientResult {
	scriptPath := filepath.Join(repoRoot, "sdk", "node", "e2e-client.ts")
	return runCLI(ctx, "npx", []string{
		"tsx", scriptPath,
		"--server", serverURL,
		"--id", id,
		"--code", code,
		"--send", sendMsg,
	}, filepath.Join(repoRoot, "sdk", "node"), nil)
}

// runSwiftClient runs the Swift E2E client and returns the result.
func runSwiftClient(ctx context.Context, serverURL, id, code, sendMsg string) clientResult {
	return runCLI(ctx, swiftE2EBin, []string{
		"--server", serverURL,
		"--id", id,
		"--code", code,
		"--send", sendMsg,
	}, "", nil)
}

// runCLI runs a CLI command and parses the first JSON line from stdout.
func runCLI(ctx context.Context, bin string, args []string, dir string, env []string) clientResult {
	cmd := exec.CommandContext(ctx, bin, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	res := clientResult{
		Stderr: stderr.String(),
		Err:    err,
	}

	// Parse first JSON line from stdout
	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var msg struct {
			From string `json:"from"`
			Data string `json:"data"`
		}
		if jsonErr := json.Unmarshal([]byte(line), &msg); jsonErr != nil {
			continue
		}
		res.ReceivedFrom = msg.From

		// Try standard base64 first, then raw-url base64
		decoded, decErr := base64.StdEncoding.DecodeString(msg.Data)
		if decErr != nil {
			decoded, decErr = base64.RawURLEncoding.DecodeString(msg.Data)
		}
		if decErr == nil {
			res.ReceivedData = string(decoded)
		} else {
			res.ReceivedData = msg.Data
		}
		break
	}

	return res
}

type clientRunner func(ctx context.Context, serverURL, id, code, sendMsg string) clientResult

func TestCrossLanguagePairing(t *testing.T) {
	port, err := getFreePort()
	if err != nil {
		t.Fatalf("get free port: %v", err)
	}

	cancel := startServer(t, port)
	defer cancel()

	serverURL := fmt.Sprintf("ws://127.0.0.1:%d/v1/connect", port)

	type testCase struct {
		name    string
		clientA struct {
			name   string
			runner clientRunner
		}
		clientB struct {
			name   string
			runner clientRunner
		}
	}

	type pair struct {
		nameA, nameB string
		runA, runB   clientRunner
	}

	pairs := []pair{
		{"go", "go", runGoClient, runGoClient},
		{"go", "python", runGoClient, runPythonClient},
		{"go", "node", runGoClient, runNodeClient},
		{"python", "node", runPythonClient, runNodeClient},
	}

	// Add Swift pairs if binary is available
	if swiftE2EBin != "" {
		pairs = append(pairs,
			pair{"go", "swift", runGoClient, runSwiftClient},
			pair{"python", "swift", runPythonClient, runSwiftClient},
			pair{"node", "swift", runNodeClient, runSwiftClient},
		)
	}

	cases := make([]testCase, len(pairs))
	for i, p := range pairs {
		cases[i].name = p.nameA + "-" + p.nameB
		cases[i].clientA.name = p.nameA
		cases[i].clientA.runner = p.runA
		cases[i].clientB.name = p.nameB
		cases[i].clientB.runner = p.runB
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			code := fmt.Sprintf("test-code-%s-%d", tc.name, rand.Int())
			msgA := fmt.Sprintf("hello from %s-A", tc.clientA.name)
			msgB := fmt.Sprintf("hello from %s-B", tc.clientB.name)
			idA := fmt.Sprintf("%s-A-%d", tc.clientA.name, rand.Int())
			idB := fmt.Sprintf("%s-B-%d", tc.clientB.name, rand.Int())

			var wg sync.WaitGroup
			var resultA, resultB clientResult

			wg.Add(2)
			go func() {
				defer wg.Done()
				resultA = tc.clientA.runner(ctx, serverURL, idA, code, msgA)
			}()
			go func() {
				defer wg.Done()
				resultB = tc.clientB.runner(ctx, serverURL, idB, code, msgB)
			}()
			wg.Wait()

			// Log stderr for debugging
			t.Logf("Client A (%s) stderr:\n%s", tc.clientA.name, resultA.Stderr)
			t.Logf("Client B (%s) stderr:\n%s", tc.clientB.name, resultB.Stderr)

			// Check for errors
			if resultA.Err != nil {
				t.Fatalf("Client A (%s) failed: %v\nstderr: %s", tc.clientA.name, resultA.Err, resultA.Stderr)
			}
			if resultB.Err != nil {
				t.Fatalf("Client B (%s) failed: %v\nstderr: %s", tc.clientB.name, resultB.Err, resultB.Stderr)
			}

			// Verify A received B's message
			if resultA.ReceivedData != msgB {
				t.Errorf("Client A (%s) expected to receive %q but got %q", tc.clientA.name, msgB, resultA.ReceivedData)
			}

			// Verify B received A's message
			if resultB.ReceivedData != msgA {
				t.Errorf("Client B (%s) expected to receive %q but got %q", tc.clientB.name, msgA, resultB.ReceivedData)
			}

			t.Logf("SUCCESS: %s received %q, %s received %q",
				tc.clientA.name, resultA.ReceivedData,
				tc.clientB.name, resultB.ReceivedData)
		})
	}
}
