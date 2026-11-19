package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// guide writes a minimal guide that passes every rule, with extra files on top.
func guide(t *testing.T, extra map[string]string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{"docs/README.md": "# Guide\n"}
	for _, p := range pages[1:] {
		files["docs/README.md"] += "- [" + p + "](" + p + ")\n"
		files["docs/"+p] = "# " + p + "\n\n## A heading\n\nBack to the [index](README.md).\n"
	}
	files["examples/app/main.go"] = "package main\n"
	for k, v := range extra {
		files[k] = v
	}
	for name, body := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestACompleteGuidePasses(t *testing.T) {
	root := guide(t, map[string]string{"docs/webhooks.md": "# Webhooks\n\n## Checking the signature\n\nSee [the API](protecting-an-api.md#a-heading), " +
		"[this](#checking-the-signature), [the example](../examples/app/main.go) and [the site](https://example.com).\n"})
	if problems := check(root, "docs"); len(problems) != 0 {
		t.Fatalf("expected none, got %q", problems)
	}
}

func TestEachRuleFails(t *testing.T) {
	cases := map[string]struct {
		extra map[string]string
		want  string
	}{
		"a missing page":         {map[string]string{"docs/enterprise.md": ""}, "enterprise.md"},
		"a page the index skips": {map[string]string{"docs/README.md": "# Guide\n"}, "doesn't link to"},
		"a missing file":         {map[string]string{"docs/webhooks.md": "[x](webhook.md)\n"}, "missing file"},
		"a missing heading":      {map[string]string{"docs/webhooks.md": "[x](signing-in.md#nowhere)\n"}, "missing heading"},
		"a link outside":         {map[string]string{"docs/webhooks.md": "[x](../../secret.md)\n"}, "outside the repository"},
		"plain http":             {map[string]string{"docs/webhooks.md": "[x](http://example.com)\n"}, "plain http"},
		"an ADR link":            {map[string]string{"docs/webhooks.md": "[x](../docs/adr/0001-x.md)\n"}, "ADR link"},
		"a sprint number":        {map[string]string{"docs/webhooks.md": "Since Sprint 12, …\n"}, "sprint number"},
		"an operator setting":    {map[string]string{"docs/webhooks.md": "Set GK_SECRET.\n"}, "operator setting"},
		"PlugPoint":              {map[string]string{"docs/webhooks.md": "As PlugPoint does.\n"}, "PlugPoint"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tc.extra["docs/enterprise.md"] == "" && name == "a missing page" {
				root := guide(t, nil)
				if err := os.Remove(filepath.Join(root, "docs/enterprise.md")); err != nil {
					t.Fatal(err)
				}
				assertProblem(t, check(root, "docs"), tc.want)
				return
			}
			assertProblem(t, check(guide(t, tc.extra), "docs"), tc.want)
		})
	}
}

func assertProblem(t *testing.T, problems []string, want string) {
	t.Helper()
	for _, p := range problems {
		if strings.Contains(p, want) {
			return
		}
	}
	t.Fatalf("no problem mentions %q in %q", want, problems)
}

func TestSlugFollowsGitHub(t *testing.T) {
	for in, want := range map[string]string{
		"Push approval on the user's phone":   "push-approval-on-the-users-phone",
		"2. Sign users in":                    "2-sign-users-in",
		"Step-up: asking for a recent factor": "step-up-asking-for-a-recent-factor",
		"`/Me` and SCIM":                      "me-and-scim",
	} {
		if got := slug(in); got != want {
			t.Errorf("slug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSamplesWritesEachCompileBlockOfOneLanguage(t *testing.T) {
	root := guide(t, map[string]string{"docs/webhooks.md": "# W\n\n```go compile\npackage main\n```\n\n```go\nfragment()\n```\n\n```ts compile\nexport {};\n```\n"})
	out := t.TempDir()
	files, err := samples(filepath.Join(root, "docs"), "go", out)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("want one go sample, got %q", files)
	}
	b, err := os.ReadFile(filepath.Join(out, files[0])) // #nosec G304 -- the test's own directory
	if err != nil || string(b) != "package main\n" {
		t.Fatalf("sample %q: %q %v", files[0], b, err)
	}
	if _, err := samples(filepath.Join(root, "docs"), "cobol", out); err == nil {
		t.Fatal("an unknown language is an error")
	}
}
