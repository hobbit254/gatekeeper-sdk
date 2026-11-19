// Command guidecheck keeps the integration guide in docs/ honest (ADR-0135):
//
//	guidecheck check docs               pages, index, links, anchors, nothing internal
//	guidecheck samples docs go out/     write each "go compile" block to out/ as a file
//
// It runs in this repository's CI, and the server repository runs it too.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// pages is the guide; README.md is its index and must link every other page.
var pages = []string{"README.md", "getting-started.md", "signing-in.md", "protecting-an-api.md",
	"machine-to-machine.md", "webhooks.md", "admin-api.md", "enterprise.md", "tenant-policies.md"}

var (
	mdLink    = regexp.MustCompile(`\]\(([^)\s]+)\)`)
	mdHeading = regexp.MustCompile(`(?m)^#{1,6} +(.+?) *$`)
	mdFence   = regexp.MustCompile("(?ms)^```([a-z]+)( compile)?\n(.*?)^```")
	// internal names things an integrator can't open or act on.
	internal = []struct {
		what string
		re   *regexp.Regexp
	}{
		{"an ADR link", regexp.MustCompile(`\]\([^)]*adr/`)},
		{"PlugPoint", regexp.MustCompile(`(?i)plugpoint`)},
		{"a sprint number", regexp.MustCompile(`\bSprint \d+`)},
		{"an operator setting", regexp.MustCompile(`\bGK_[A-Z0-9_]+`)},
	}
	extensions = map[string]string{"go": ".go", "ts": ".ts", "php": ".php", "dart": ".dart"}
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "check" {
		problems := check(".", os.Args[2])
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, p)
		}
		if len(problems) > 0 {
			os.Exit(1)
		}
		fmt.Println("the guide is complete, linked and public")
		return
	}
	if len(os.Args) == 5 && os.Args[1] == "samples" {
		files, err := samples(os.Args[2], os.Args[3], os.Args[4])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(strings.Join(files, "\n"))
		return
	}
	fmt.Fprintln(os.Stderr, "usage: guidecheck check <docs> | guidecheck samples <docs> <go|ts|php|dart> <out>")
	os.Exit(2)
}

// readGuide reads every Markdown file under root/docs, keyed by its path there.
func readGuide(root, docs string) (map[string]string, error) {
	files := map[string]string{}
	base := filepath.Join(root, docs)
	err := filepath.WalkDir(base, func(p string, d os.DirEntry, err error) error { // #nosec G703 -- a directory named on the command line
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".md") {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 G122 -- the repository's own guide
		rel, _ := filepath.Rel(base, p)
		files[filepath.ToSlash(rel)] = string(b)
		return err
	})
	return files, err
}

// check returns every rule the guide under root/docs breaks, in a stable order.
func check(root, docs string) []string {
	files, err := readGuide(root, docs)
	if err != nil {
		return []string{err.Error()}
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }
	for _, p := range pages {
		if _, ok := files[p]; !ok {
			add("the guide has no %s", p)
		} else if p != "README.md" && !strings.Contains(files["README.md"], "]("+p+")") {
			add("README.md doesn't link to %s", p)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	repo, _ := filepath.Abs(root)
	for _, name := range names {
		md := files[name]
		for _, rule := range internal {
			if m := rule.re.FindString(md); m != "" {
				add("%s has %s: %q", name, rule.what, m)
			}
		}
		for _, m := range mdLink.FindAllStringSubmatch(md, -1) {
			link := m[1]
			switch {
			case strings.HasPrefix(link, "https://"), strings.HasPrefix(link, "mailto:"):
				continue
			case strings.HasPrefix(link, "http://"):
				add("%s links over plain http: %s", name, link)
				continue
			}
			path, frag, _ := strings.Cut(link, "#")
			target := name
			if path != "" {
				target = filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(name), path)))
				abs := filepath.Join(repo, docs, target)
				if rel, err := filepath.Rel(repo, abs); err != nil || strings.HasPrefix(rel, "..") {
					add("%s links outside the repository: %s", name, link)
					continue
				}
				if _, err := os.Stat(abs); err != nil { // #nosec G703 -- confined to the repository just above
					add("%s links to a missing file: %s", name, link)
					continue
				}
			}
			if frag == "" {
				continue
			}
			if md, ok := files[target]; !ok {
				add("%s has an anchor into a file outside the guide: %s", name, link)
			} else if !anchors(md)[frag] {
				add("%s links to a missing heading: %s", name, link)
			}
		}
	}
	return problems
}

// slug is GitHub's anchor for a heading: lower case, punctuation dropped, spaces to dashes.
func slug(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.ReplaceAll(heading, "`", "")) {
		switch {
		case r == ' ':
			b.WriteRune('-')
		case r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return strings.TrimLeft(b.String(), "-")
}

func anchors(md string) map[string]bool {
	set := map[string]bool{}
	for _, m := range mdHeading.FindAllStringSubmatch(md, -1) {
		set[slug(m[1])] = true
	}
	return set
}

// samples writes each "<lang> compile" block under docs to out, one file per
// block, and returns the file names. Other blocks are fragments for reading.
func samples(docs, lang, out string) ([]string, error) {
	ext, ok := extensions[lang]
	if !ok {
		return nil, fmt.Errorf("%q samples can't be compiled; use go, ts, php or dart", lang)
	}
	files, err := readGuide(docs, ".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var written []string
	for _, name := range names {
		for i, m := range mdFence.FindAllStringSubmatch(files[name], -1) {
			if m[2] == "" || m[1] != lang {
				continue
			}
			file := strings.NewReplacer("/", "_", ".md", "").Replace(name) + fmt.Sprintf("_%d", i) + ext
			if lang == "go" { // each Go sample is its own main package
				file = filepath.Join(strings.TrimSuffix(file, ext), "main.go")
			}
			p := filepath.Join(out, file)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil { // #nosec G703 -- under the output directory named on the command line
				return nil, err
			}
			if err := os.WriteFile(p, []byte(m[3]), 0o600); err != nil { // #nosec G703 -- as above
				return nil, err
			}
			written = append(written, file)
		}
	}
	return written, nil
}
