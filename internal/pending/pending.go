// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

// Package pending finds the transfers an interrupted send or decrypt left on
// disk, so they can be finished or discarded.
package pending

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/deepsecret-io/sdk"
	"github.com/deepsecret-io/sdk/api"
	"github.com/google/uuid"

	"github.com/deepsecret-io/cli/internal/config"
	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/logging"
	"github.com/deepsecret-io/cli/internal/ui"
)

// UploadsDir is where large sends keep their encrypted payload until the
// upload finishes, so `secret resume` can finish an interrupted one.
// DEEPSECRET_TMPDIR moves it, as it moves the other temporary files; the
// folder there is named for the user, since that directory may be shared,
// and the SDK refuses it unless it is private to this user.
func UploadsDir() string {
	if dir := os.Getenv(sdk.TempDirEnv); dir != "" {
		return filepath.Join(dir, "deepsecret-uploads-"+userTag())
	}
	return filepath.Join(config.Dir(), "uploads")
}

// DownloadsDir is where large decrypts keep what they downloaded until the
// payload is decrypted, so an interrupted decrypt continues where it
// stopped when run again. DEEPSECRET_TMPDIR moves it, as it moves
// UploadsDir.
func DownloadsDir() string {
	if dir := os.Getenv(sdk.TempDirEnv); dir != "" {
		return filepath.Join(dir, "deepsecret-downloads-"+userTag())
	}
	return filepath.Join(config.Dir(), "downloads")
}

// userTag names this user in a folder name: the numeric user ID on Unix,
// and the account name on Windows, which has no user IDs.
func userTag() string {
	if uid := os.Getuid(); uid >= 0 {
		return strconv.Itoa(uid)
	}
	if u, err := user.Current(); err == nil {
		name := u.Username[strings.LastIndexAny(u.Username, `\/`)+1:] // DOMAIN\name
		name = strings.Map(func(r rune) rune {
			if r < 0x80 && (unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-') {
				return r
			}
			return '_'
		}, name)
		if name != "" {
			return name
		}
	}
	return "user"
}

// UploadIDPattern is an upload or download ID, or its first 4 or more
// characters.
var UploadIDPattern = regexp.MustCompile(`^[0-9a-f][0-9a-f-]{3,35}$`)

// Find picks the interrupted upload or download whose ID is, or
// starts with, id; one of the two results is set.
func Find(uploads []sdk.PendingUpload, downloads []sdk.PendingDownload, id string) (*sdk.PendingUpload, *sdk.PendingDownload, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	var up []*sdk.PendingUpload
	var down []*sdk.PendingDownload
	for i := range uploads {
		switch p := &uploads[i]; {
		case p.RevisionID == id:
			return p, nil, nil
		case len(id) >= 4 && strings.HasPrefix(p.RevisionID, id):
			up = append(up, p)
		}
	}
	for i := range downloads {
		switch d := &downloads[i]; {
		case d.RevisionID == id:
			return nil, d, nil
		case len(id) >= 4 && strings.HasPrefix(d.RevisionID, id):
			down = append(down, d)
		}
	}
	switch n := len(up) + len(down); {
	case n == 0:
		return nil, nil, errs.WithDetail(fmt.Errorf("no interrupted upload or download %q", id), "List them with: secret resume")
	case n > 1:
		return nil, nil, fmt.Errorf("%q matches %d transfers; give more of the ID", id, n)
	case len(up) == 1:
		return up[0], nil, nil
	default:
		return nil, down[0], nil
	}
}

// DiscardDownload removes a kept download with --discard. Without it, it
// says how to continue the download: by decrypting again, which keeps the
// decrypt's own output choices.
func DiscardDownload(d *sdk.PendingDownload, discard bool) error {
	if !discard {
		detail := "A download continues when you decrypt it again."
		// The secret ID comes from a local file: it goes into a command
		// to copy only as the UUID it must be.
		if id, err := uuid.Parse(d.SecretID); err == nil && id.String() == d.SecretID {
			detail = "A download continues when you decrypt it again:\n  secret decrypt " + d.SecretID + " --revision " + d.RevisionID
		}
		return errs.WithDetail(fmt.Errorf("%s is an interrupted download, which resume does not finish", ui.ShortID(d.RevisionID)), detail)
	}
	if err := sdk.DiscardPendingDownload(DownloadsDir(), d.RevisionID); err != nil {
		return fmt.Errorf("could not discard the download of %q: %w", d.Name, err)
	}
	api.Module(logging.Log, "resume").Info("download discarded", "revision_id", d.RevisionID, "secret_id", d.SecretID)
	ui.Success(fmt.Sprintf("Discarded the download of %q.", d.Name))
	return nil
}
