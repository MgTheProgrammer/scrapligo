package cli_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	scrapligocli "github.com/scrapli/scrapligo/v2/cli"
	scrapligoconstants "github.com/scrapli/scrapligo/v2/constants"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
	scrapligooptions "github.com/scrapli/scrapligo/v2/options"
	scrapligotesthelper "github.com/scrapli/scrapligo/v2/testhelper"
)

func TestOpenWithKey(t *testing.T) {
	parentName := "open-with-key"

	cases := map[string]struct {
		description string
		options     []scrapligooptions.Option
	}{
		"bin": {
			description: "simple-bin",
			options: []scrapligooptions.Option{
				scrapligooptions.WithDefinitionFileOrName(scrapligocli.AristaEos),
				scrapligooptions.WithTransportBin(),
				scrapligooptions.WithUsername("admin-sshkey"),
				scrapligooptions.WithPrivateKeyPath("./fixtures/libscrapli_test_ssh_key"),
				scrapligooptions.WithLookupKeyValue("enable", "libscrapli"),
			},
		},
		"ssh2": {
			description: "simple-ssh2",
			options: []scrapligooptions.Option{
				scrapligooptions.WithDefinitionFileOrName(scrapligocli.AristaEos),
				scrapligooptions.WithTransportSSH2(),
				scrapligooptions.WithUsername("admin-sshkey"),
				scrapligooptions.WithPrivateKeyPath("./fixtures/libscrapli_test_ssh_key"),
				scrapligooptions.WithLookupKeyValue("enable", "libscrapli"),
			},
		},
		"bin-passhprase": {
			description: "bin-with-passhrase",
			options: []scrapligooptions.Option{
				scrapligooptions.WithDefinitionFileOrName(scrapligocli.AristaEos),
				scrapligooptions.WithTransportBin(),
				scrapligooptions.WithUsername("admin-sshkey-passphrase"),
				scrapligooptions.WithPrivateKeyPath(
					"./fixtures/libscrapli_test_ssh_key_passphrase",
				),
				scrapligooptions.WithPrivateKeyPassphrase("libscrapli"),
				scrapligooptions.WithLookupKeyValue("enable", "libscrapli"),
			},
		},
		"ssh2-passhrase": {
			description: "ssh2-with-passhrase",
			options: []scrapligooptions.Option{
				scrapligooptions.WithDefinitionFileOrName(scrapligocli.AristaEos),
				scrapligooptions.WithTransportSSH2(),
				scrapligooptions.WithUsername("admin-sshkey-passphrase"),
				scrapligooptions.WithPrivateKeyPath(
					"./fixtures/libscrapli_test_ssh_key_passphrase",
				),
				scrapligooptions.WithPrivateKeyPassphrase("libscrapli"),
				scrapligooptions.WithLookupKeyValue("enable", "libscrapli"),
			},
		},
	}

	for caseName, caseData := range cases {
		testName := fmt.Sprintf("%s-%s", parentName, caseName)

		t.Run(testName, func(t *testing.T) {
			t.Logf("%s: starting", testName)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			var host string

			if !scrapligotesthelper.EosAvailable() {
				t.Skip("skipping case, arista eos unavailable...")
			}

			var port uint16

			if runtime.GOOS == scrapligoconstants.Darwin {
				host = localhost
				port = 22022
			} else {
				host = "172.20.20.17"
			}

			caseData.options = append(
				caseData.options,
				scrapligooptions.WithPort(port),
			)

			c, err := scrapligocli.NewCli(
				host,
				caseData.options...,
			)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				_, _ = c.Close(ctx)
			}()

			_, err = c.Open(ctx)
			if err != nil {
				t.Fatal(err)
			}

			// no need to assert result, just make sure getprompt works
			_, err = c.GetPrompt(ctx)
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestOpenAuthenticationFailure(t *testing.T) {
	parentName := "open-authentication-failure"

	// the certificate is signed by a ca the device doesnt trust, and the "admin" user has no
	// authorized key, so key/certificate auth is rejected
	certificateOptions := []scrapligooptions.Option{
		scrapligooptions.WithPrivateKeyPath("./fixtures/libscrapli_test_ssh_key"),
		scrapligooptions.WithCertificatePath("./fixtures/libscrapli_test_ssh_key-cert.pub"),
	}

	cases := map[string]struct {
		transport scrapligooptions.Option
		options   []scrapligooptions.Option
	}{
		"srl-bin-bad-password": {
			transport: scrapligooptions.WithTransportBin(),
			options: []scrapligooptions.Option{
				scrapligooptions.WithPassword("not-the-password"),
			},
		},
		"srl-ssh2-bad-password": {
			transport: scrapligooptions.WithTransportSSH2(),
			options: []scrapligooptions.Option{
				scrapligooptions.WithPassword("not-the-password"),
			},
		},
		"srl-bin-untrusted-certificate": {
			transport: scrapligooptions.WithTransportBin(),
			options:   certificateOptions,
		},
		"srl-ssh2-untrusted-certificate": {
			transport: scrapligooptions.WithTransportSSH2(),
			options:   certificateOptions,
		},
	}

	for caseName, caseData := range cases {
		testName := fmt.Sprintf("%s-%s", parentName, caseName)

		t.Run(testName, func(t *testing.T) {
			t.Logf("%s: starting", testName)

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			host := "172.20.20.16"
			port := uint16(22)

			if runtime.GOOS == scrapligoconstants.Darwin {
				host = localhost
				port = 21022
			}

			opts := append(
				[]scrapligooptions.Option{
					scrapligooptions.WithDefinitionFileOrName(scrapligocli.NokiaSrlinux.String()),
					caseData.transport,
					scrapligooptions.WithUsername("admin"),
					scrapligooptions.WithPort(port),
				},
				caseData.options...,
			)

			c, err := scrapligocli.NewCli(
				host,
				opts...,
			)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				_, _ = c.Close(ctx)
			}()

			_, err = c.Open(ctx)
			if !errors.Is(err, scrapligoerrors.ErrAuthentication) {
				t.Fatalf("expected authentication error, got: %v", err)
			}
		})
	}
}
