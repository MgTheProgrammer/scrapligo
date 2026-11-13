package netconf_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	scrapligocli "github.com/scrapli/scrapligo/v2/cli"
	scrapligoconstants "github.com/scrapli/scrapligo/v2/constants"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
	scrapligonetconf "github.com/scrapli/scrapligo/v2/netconf"
	scrapligooptions "github.com/scrapli/scrapligo/v2/options"
	scrapligotesthelper "github.com/scrapli/scrapligo/v2/testhelper"
)

func TestSSH2TransportProxyJumpNetconf(t *testing.T) {
	parentName := "ssh2-transport-proxy-jump-netconf"

	cases := map[string]struct {
		description string
		platform    string
		filter      string
	}{
		"eos": {
			description: "simple",
			platform:    scrapligocli.AristaEos.String(),
			filter:      "<system><config><hostname></hostname></config></system>",
		},
		"srl": {
			description: "simple",
			platform:    scrapligocli.NokiaSrlinux.String(),
			filter:      "<system xmlns=\"urn:nokia.com:srlinux:general:system\"><ssh-server xmlns=\"urn:nokia.com:srlinux:linux:ssh\"><name>mgmt</name></ssh-server></system>",
		},
	}

	for caseName, caseData := range cases {
		testName := fmt.Sprintf("%s-%s", parentName, caseName)

		t.Run(testName, func(t *testing.T) {
			t.Logf("%s: starting", testName)

			testGoldenPath, err := filepath.Abs(fmt.Sprintf("./golden/%s", testName))
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			var host string

			opts := []scrapligooptions.Option{
				scrapligooptions.WithUsername("scrapli-pw"),
				scrapligooptions.WithPassword("scrapli-123-pw"),
				scrapligooptions.WithTransportSSH2(),
			}

			if runtime.GOOS == scrapligoconstants.Darwin {
				host = localhost

				opts = append(
					opts,
					scrapligooptions.WithPort(24022),
				)
			} else {
				host = "172.20.20.19"

				// wants to default to 830, but we are jumping through the jumper host on 22
				opts = append(
					opts,
					scrapligooptions.WithPort(22),
				)
			}

			if caseData.platform == scrapligocli.AristaEos.String() {
				if !scrapligotesthelper.EosAvailable() {
					t.Skip("skipping case, arista eos unavailable...")
				}

				opts = append(
					opts,
					scrapligooptions.WithSSH2ProxyJumpHost("172.20.20.17"),
					scrapligooptions.WithSSH2ProxyJumpUsername("admin"),
					scrapligooptions.WithSSH2ProxyJumpPassword("admin"),
					scrapligooptions.WithLookupKeyValue("enable", "libscrapli"),
				)
			} else {
				opts = append(
					opts,
					scrapligooptions.WithSSH2ProxyJumpHost("172.20.20.16"),
					scrapligooptions.WithSSH2ProxyJumpPort(830),
					scrapligooptions.WithSSH2ProxyJumpUsername("admin"),
					scrapligooptions.WithSSH2ProxyJumpPassword("NokiaSrl1!"),
				)
			}

			n, err := scrapligonetconf.NewNetconf(
				host,
				opts...,
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = n.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				_, _ = n.Close(ctx)
			}()

			r, err := n.Get(ctx, scrapligonetconf.WithFilter(caseData.filter))
			if err != nil {
				t.Fatal(err)
			}

			assertResult(t, r, testGoldenPath)
		})
	}
}

func openNetconfForHostKeyFingerprint(
	ctx context.Context,
	t *testing.T,
	n *scrapligonetconf.Netconf,
	hash scrapligoconstants.HostKeyHash,
) ([]byte, error) {
	t.Helper()

	_, err := n.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_, _ = n.Close(ctx)
	}()

	return n.GetHostKeyFingerprint(hash)
}

func TestSSH2TransportHostKeyFingerprintProxyJump(t *testing.T) {
	parentName := "ssh2-transport-host-key-fingerprint-proxy-jump"

	cases := map[string]struct {
		hash     scrapligoconstants.HostKeyHash
		expected int
	}{
		"md5": {
			hash:     scrapligoconstants.HostKeyHashMD5,
			expected: 16,
		},
		"sha1": {
			hash:     scrapligoconstants.HostKeyHashSHA1,
			expected: 20,
		},
		"sha256": {
			hash:     scrapligoconstants.HostKeyHashSHA256,
			expected: 32,
		},
	}

	for caseName, caseData := range cases {
		testName := fmt.Sprintf("%s-%s", parentName, caseName)

		t.Run(testName, func(t *testing.T) {
			t.Logf("%s: starting", testName)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			direct, err := openNetconfForHostKeyFingerprint(
				ctx,
				t,
				getNetconf(t, "netopeer", "ssh2"),
				caseData.hash,
			)
			if err != nil {
				t.Fatal(err)
			}

			if len(direct) != caseData.expected {
				t.Fatalf("unexpected digest length %d: %x", len(direct), direct)
			}

			host := "172.20.20.19"

			opts := []scrapligooptions.Option{
				scrapligooptions.WithUsername("scrapli-pw"),
				scrapligooptions.WithPassword("scrapli-123-pw"),
				scrapligooptions.WithTransportSSH2(),
				// always the clab address since this is resolved from the jump host
				scrapligooptions.WithSSH2ProxyJumpHost("172.20.20.18"),
				scrapligooptions.WithSSH2ProxyJumpPort(830),
				scrapligooptions.WithSSH2ProxyJumpUsername("root"),
				scrapligooptions.WithSSH2ProxyJumpPassword("password"),
			}

			if runtime.GOOS == scrapligoconstants.Darwin {
				host = localhost

				opts = append(opts, scrapligooptions.WithPort(24022))
			} else {
				opts = append(opts, scrapligooptions.WithPort(22))
			}

			n, err := scrapligonetconf.NewNetconf(host, opts...)
			if err != nil {
				t.Fatal(err)
			}

			proxied, err := openNetconfForHostKeyFingerprint(ctx, t, n, caseData.hash)
			if err != nil {
				t.Fatal(err)
			}

			// when proxy jumping we should get the target device, not the jump host
			if !bytes.Equal(proxied, direct) {
				t.Fatalf("proxied digest %x does not match direct %x", proxied, direct)
			}
		})
	}
}

func TestBinTransportHostKeyFingerprintUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := openNetconfForHostKeyFingerprint(
		ctx,
		t,
		getNetconf(t, "netopeer", "bin"),
		scrapligoconstants.HostKeyHashSHA256,
	)
	if !errors.Is(err, scrapligoerrors.ErrOperation) {
		t.Fatalf("expected ErrOperation, got: %v", err)
	}
}
