package netconf_test

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	scrapligoconstants "github.com/scrapli/scrapligo/v2/constants"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
	scrapligonetconf "github.com/scrapli/scrapligo/v2/netconf"
	scrapligooptions "github.com/scrapli/scrapligo/v2/options"
)

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
			port := uint16(830)

			if runtime.GOOS == scrapligoconstants.Darwin {
				host = localhost
				port = 21830
			}

			opts := append(
				[]scrapligooptions.Option{
					caseData.transport,
					scrapligooptions.WithUsername("admin"),
					scrapligooptions.WithPort(port),
				},
				caseData.options...,
			)

			n, err := scrapligonetconf.NewNetconf(
				host,
				opts...,
			)
			if err != nil {
				t.Fatal(err)
			}

			defer func() {
				_, _ = n.Close(ctx)
			}()

			_, err = n.Open(ctx)
			if !errors.Is(err, scrapligoerrors.ErrAuthentication) {
				t.Fatalf("expected authentication error, got: %v", err)
			}
		})
	}
}
