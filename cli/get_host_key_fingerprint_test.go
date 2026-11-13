package cli_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	scrapligoconstants "github.com/scrapli/scrapligo/v2/constants"
	scrapligoerrors "github.com/scrapli/scrapligo/v2/errors"
)

func TestGetHostKeyFingerprintNotSSH2(t *testing.T) {
	// the test transport never sees a host key, so we should get the "no fingerprint" error back
	testFixturePath, err := filepath.Abs(fmt.Sprintf("./fixtures/%s", "get-prompt"))
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c := getCli(t, testFixturePath)

	_, err = c.Open(ctx)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		_, _ = c.Close(ctx)
	}()

	_, err = c.GetHostKeyFingerprint(scrapligoconstants.HostKeyHashSHA256)
	if !errors.Is(err, scrapligoerrors.ErrOperation) {
		t.Fatalf("expected ErrOperation, got: %v", err)
	}
}
