package cli_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	scrapligocli "github.com/scrapli/scrapligo/v2/cli"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
	scrapligooptions "github.com/scrapli/scrapligo/v2/options"
	scrapligotesthelper "github.com/scrapli/scrapligo/v2/testhelper"
)

func TestOpenErrors(t *testing.T) {
	cases := map[string]struct {
		port     func(t *testing.T) uint16
		options  []scrapligooptions.Option
		ctx      func(t *testing.T) context.Context
		expected error
	}{
		"connection-refused": {
			port:     scrapligotesthelper.ClosedPort,
			expected: scrapligoerrors.ErrSession,
		},
		"operation-timeout": {
			port: scrapligotesthelper.SilentServer,
			options: []scrapligooptions.Option{
				scrapligooptions.WithOperationTimeout(time.Second),
			},
			expected: scrapligoerrors.ErrTimeout,
		},
		"context-deadline": {
			port: scrapligotesthelper.SilentServer,
			ctx: func(t *testing.T) context.Context {
				t.Helper()

				ctx, cancel := context.WithTimeout(t.Context(), time.Second)
				t.Cleanup(cancel)

				return ctx
			},
			expected: context.DeadlineExceeded,
		},
		"context-cancelled": {
			port: scrapligotesthelper.SilentServer,
			ctx: func(t *testing.T) context.Context {
				t.Helper()

				ctx, cancel := context.WithCancel(t.Context())
				time.AfterFunc(time.Second, cancel)
				t.Cleanup(cancel)

				return ctx
			},
			expected: context.Canceled,
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			if c.ctx != nil {
				ctx = c.ctx(t)
			}

			d, err := scrapligocli.NewCli(
				"127.0.0.1",
				append(c.options, scrapligooptions.WithPort(c.port(t)))...,
			)
			if err != nil {
				t.Fatal(err)
			}

			_, err = d.Open(ctx)
			if !errors.Is(err, c.expected) {
				t.Fatalf("expected errors.Is(err, %v), got %v", c.expected, err)
			}
		})
	}
}

// TestOpenAuthenticationFailure replays recorded (srl, bin transport) sessions in which the device
// rejects our credentials.
func TestOpenAuthenticationFailure(t *testing.T) {
	cases := map[string][]scrapligooptions.Option{
		// wrong password -- the device keeps prompting for the password
		"password-reprompted": {
			scrapligooptions.WithPassword("not-the-password"),
		},
		// key rejected, ssh falls back to a password prompt but there is no password to send
		"key-rejected-password-prompted": nil,
		// key rejected, no other auth methods to fall back to
		"key-rejected-permission-denied": nil,
	}

	for name, options := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := filepath.Abs("./fixtures/open-authentication-failure-" + name)
			if err != nil {
				t.Fatal(err)
			}

			d, err := scrapligocli.NewCli(
				testHost,
				append(
					[]scrapligooptions.Option{
						scrapligooptions.WithUsername("admin"),
						scrapligooptions.WithDefinitionFileOrName(scrapligocli.NokiaSrlinux),
						scrapligooptions.WithTransportTest(),
						scrapligooptions.WithTestTransportF(f),
						scrapligooptions.WithReadSize(1),
					},
					options...,
				)...,
			)
			if err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()

			_, err = d.Open(ctx)
			if !errors.Is(err, scrapligoerrors.ErrAuthentication) {
				t.Fatalf("expected errors.Is(err, ErrAuthentication), got %v", err)
			}
		})
	}
}
