package dashboard

import (
	"io/fs"
	"path"
	"regexp"
	"strings"
	"testing"
)

var (
	htmlRef   = regexp.MustCompile(`(?:src|href)="([^"]+)"`)
	jsImport  = regexp.MustCompile(`(?m)(?:^\s*import\s[^'"]*?from\s*|^\s*import\s*|^\s*export\s[^'"]*?from\s*|import\()\s*['"](\.{1,2}/[^'"]+)['"]`)
	cssImport = regexp.MustCompile(`(?:@import\s+(?:url\()?|url\()\s*['"]?([^'")\s]+)`)
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(FS, name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

// TestAssetsResolve walks every asset reachable from index.html (HTML refs,
// ES module imports, CSS imports/urls) and checks each one is embedded.
func TestAssetsResolve(t *testing.T) {
	index := read(t, "index.html")
	var queue []string
	for _, m := range htmlRef.FindAllStringSubmatch(index, -1) {
		ref := m[1]
		if strings.HasPrefix(ref, "#") || strings.Contains(ref, "://") || strings.HasPrefix(ref, "data:") {
			continue
		}
		queue = append(queue, strings.TrimPrefix(path.Clean(ref), "/"))
	}
	if len(queue) < 2 {
		t.Fatalf("index.html references too few assets: %v", queue)
	}
	seen := map[string]bool{}
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if seen[name] {
			continue
		}
		seen[name] = true
		body := read(t, name)
		dir := path.Dir(name)
		var refs [][]string
		switch path.Ext(name) {
		case ".js":
			refs = jsImport.FindAllStringSubmatch(body, -1)
		case ".css":
			refs = cssImport.FindAllStringSubmatch(body, -1)
		}
		for _, m := range refs {
			if strings.HasPrefix(m[1], "data:") || strings.HasPrefix(m[1], "#") {
				continue
			}
			queue = append(queue, path.Join(dir, m[1]))
		}
	}
	for _, must := range []string{"js/app.js", "js/api.js", "js/router.js", "js/charts.js", "js/mock.js", "js/fixtures.js"} {
		if !seen[must] {
			t.Errorf("%s is not reachable from index.html", must)
		}
	}
	// Every page module must be wired into the app.
	pages, err := fs.ReadDir(FS, "js/pages")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pages {
		if !seen["js/pages/"+p.Name()] {
			t.Errorf("page js/pages/%s is never imported", p.Name())
		}
	}
	t.Logf("%d assets resolved", len(seen))
}

// TestCSPSafe guards the constraints the admin CSP imposes.
func TestCSPSafe(t *testing.T) {
	index := read(t, "index.html")
	if regexp.MustCompile(`<script(?:\s[^>]*)?>\s*[^<\s]`).MatchString(index) {
		t.Error("index.html contains an inline script")
	}
	if strings.Contains(index, "<style") || strings.Contains(index, " style=") {
		t.Error("index.html contains inline styles")
	}
	noComments := regexp.MustCompile(`<!--[\s\S]*?-->`).ReplaceAllString(index, "")
	if regexp.MustCompile(`(?:src|href)="https?://`).MatchString(noComments) {
		t.Error("index.html references an external asset")
	}
	bad := []*regexp.Regexp{
		regexp.MustCompile(`\beval\(`),
		regexp.MustCompile(`new Function\(`),
		regexp.MustCompile(`style=\\?["']`),
		regexp.MustCompile(`setAttribute\(\s*['"]style['"]`),
		regexp.MustCompile(`\.innerHTML\s*=`),
		regexp.MustCompile(`\.outerHTML\s*=`),
		regexp.MustCompile(`insertAdjacentHTML`),
		regexp.MustCompile(`document\.write`),
		regexp.MustCompile(`(?:src|href)\s*[:=]\s*['"]https?://`),
	}
	err := fs.WalkDir(FS, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".js" {
			return err
		}
		body := read(t, p)
		for _, re := range bad {
			if loc := re.FindStringIndex(body); loc != nil {
				line := strings.Count(body[:loc[0]], "\n") + 1
				t.Errorf("%s:%d: CSP-unsafe pattern %q", p, line, re.String())
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIndexServedAtRoot(t *testing.T) {
	if _, err := fs.Stat(FS, "index.html"); err != nil {
		t.Fatalf("FS must be rooted at static/: %v", err)
	}
	if _, err := fs.Stat(FS, "static"); err == nil {
		t.Fatal("FS must not contain a nested static/ directory")
	}
}
