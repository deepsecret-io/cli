// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 DeepSecret

//go:build windows

package safefile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/deepsecret-io/cli/internal/errs"
	"github.com/deepsecret-io/cli/internal/testutil"
)

// Only this user, SYSTEM and Administrators may own or open what the CLI
// keeps. Anything else, and anything the check cannot read, is refused.
func TestExposure(t *testing.T) {
	me := testutil.CurrentUser(t).String()
	for _, c := range []struct {
		name, sddl string
		refused    string // part of the reason, or "" when accepted
	}{
		{"owner only", "O:" + me + "D:P(A;;FA;;;" + me + ")", ""},
		{"a profile folder's inherited entries", "O:" + me + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;" + me + ")", ""},
		{"owned by Administrators", "O:BAD:P(A;;FA;;;" + me + ")", ""},
		{"owned by SYSTEM", "O:SYD:P(A;;FA;;;" + me + ")", ""},
		{"an empty DACL", "O:" + me + "D:P", ""},
		{"a deny entry for Everyone", "O:" + me + "D:P(D;;FA;;;WD)(A;;FA;;;" + me + ")", ""},
		{"owned by Everyone", "O:WDD:P(A;;FA;;;" + me + ")", "belongs to"},
		{"no owner", "D:P(A;;FA;;;" + me + ")", "no owner"},
		{"no DACL", "O:" + me, "no access list"},
		{"a NULL DACL", "O:" + me + "D:NO_ACCESS_CONTROL", "no access list"},
		{"Everyone may read", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FR;;;WD)", "may open it"},
		{"Users inherit read", "O:" + me + "D:AI(A;ID;FR;;;BU)(A;;FA;;;" + me + ")", "may open it"},
		{"Everyone inherit-only", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;OICIIO;FA;;;WD)", "may open it"},
		{"Authenticated Users may write", "O:" + me + "D:P(A;;FA;;;" + me + ")(A;;FW;;;AU)", "may open it"},
		{"a conditional allow entry", "O:" + me + "D:P(A;;FA;;;" + me + ")(XA;;FR;;;WD;(Member_of {SID(BA)}))", "type 9"},
		{"an object allow entry", "O:" + me + "D:P(A;;FA;;;" + me + ")(OA;;FR;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)", "type 5"},
	} {
		sd, err := windows.SecurityDescriptorFromString(c.sddl)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		who, _ := exposure(sd, testutil.CurrentUser(t))
		switch {
		case c.refused == "" && who != "":
			t.Errorf("%s (%s): refused: %s", c.name, c.sddl, who)
		case c.refused != "" && !strings.Contains(who, c.refused):
			t.Errorf("%s (%s): %q, want a refusal saying %q", c.name, c.sddl, who, c.refused)
		}
	}
}

// What the CLI creates is private from the start, folders included, and
// a file plain code later creates in such a folder is private too, by
// inheriting the folder's one entry.
func TestCreatedFilesArePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := MkdirPrivate(dir); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, dir)
	testutil.AssertPrivate(t, filepath.Dir(dir))
	if err := MkdirPrivate(dir); err != nil {
		t.Fatalf("a folder already there: %v", err)
	}

	out := filepath.Join(dir, "secret.txt")
	if err := Write(out, []byte("plaintext"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, out)
	if data, err := ReadPrivate(out); err != nil || string(data) != "plaintext" {
		t.Fatalf("ReadPrivate: %q, %v", data, err)
	}

	tmp, err := CreateTemp(dir, ".config.json-*")
	if err != nil {
		t.Fatal(err)
	}
	if base := filepath.Base(tmp.Name()); !strings.HasPrefix(base, ".config.json-") || len(base) <= len(".config.json-") {
		t.Errorf("temporary file %s", base)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, tmp.Name())
	// A rename keeps the file's own ACL, so a file replaced this way is
	// private wherever it lands.
	final := filepath.Join(dir, "config.json")
	if err := os.Rename(tmp.Name(), final); err != nil {
		t.Fatal(err)
	}
	testutil.AssertPrivate(t, final)

	plain := filepath.Join(dir, "plain.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(plain, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		t.Fatalf("a file made in a private folder: %s, want the folder's one entry", sd)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !sid.Equals(testutil.CurrentUser(t)) || ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
		t.Errorf("a file made in a private folder: %s, want this user's inherited entry", sd)
	}
	if _, err := ReadPrivate(plain); err != nil {
		t.Errorf("ReadPrivate refused a file that inherits a private folder's entry: %v", err)
	}
}

// A file someone else may open is refused, with the command that fixes
// it; a link at the destination is never written through.
func TestReadPrivateRefusesAnExposedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token.json")
	if err := Write(path, []byte(`{"token":"t"}`), 0o600, false); err != nil {
		t.Fatal(err)
	}
	testutil.Expose(t, path)
	_, err := ReadPrivate(path)
	if !errors.Is(err, ErrNotPrivate) {
		t.Fatalf("an exposed file: %v, want ErrNotPrivate", err)
	}
	summary, detail := errs.Describe(err)
	if !strings.HasSuffix(summary, "token.json is open to other users") || !strings.Contains(detail, "may open it") ||
		!strings.Contains(detail, "icacls \""+path+"\" /inheritance:r /grant:r") || !strings.Contains(detail, "/remove:g") {
		t.Errorf("%q, %q", summary, detail)
	}

	testutil.SetDACL(t, path, "D:NO_ACCESS_CONTROL")
	if _, err := ReadPrivate(path); !errors.Is(err, ErrNotPrivate) {
		t.Errorf("a file with a NULL DACL: %v, want ErrNotPrivate", err)
	}
	if _, err := ReadPrivate(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Errorf("a missing file: %v, want not-exist", err)
	}
}

// A file another handle may write is not read: that handle may have been
// opened before the file's ACL was fixed.
func TestReadPrivateRefusesAFileOpenForWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := Write(path, []byte("{}"), 0o600, false); err != nil {
		t.Fatal(err)
	}
	w, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivate(path); !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Errorf("a file open for writing: %v, want a sharing violation", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := ReadPrivate(path); err != nil || string(data) != "{}" {
		t.Errorf("after the writer closed: %q, %v", data, err)
	}
}
