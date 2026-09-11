package catalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/excubra/excubra/internal/server/store"
)

// A fake GitHub: two releases with manifests, one draft, one without a manifest.
func fakeGitHub(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		manifest := func(v string) any {
			return map[string]any{"version": v, "min_agent_version": "0.1.0", "files": []map[string]string{
				{"os": "linux", "arch": "amd64", "name": "excubra_linux_amd64", "url": "https://github.com/excubra/excubra/releases/download/v" + v + "/excubra_linux_amd64", "sha256": strings.Repeat("ab", 32), "signature": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 70)))},
				{"os": "linux", "arch": "arm64", "name": "excubra_linux_arm64", "url": "https://github.com/excubra/excubra/releases/download/v" + v + "/excubra_linux_arm64", "sha256": strings.Repeat("cd", 32), "signature": base64.StdEncoding.EncodeToString([]byte(strings.Repeat("t", 70)))},
			}}
		}
		switch r.URL.Path {
		case "/releases":
			_ = json.NewEncoder(w).Encode([]map[string]any{
				{"tag_name": "v0.3.0", "draft": false, "assets": []map[string]string{{"name": "manifest.json", "browser_download_url": srv.URL + "/m/0.3.0"}}},
				{"tag_name": "v0.2.0", "draft": false, "assets": []map[string]string{{"name": "manifest.json", "browser_download_url": srv.URL + "/m/0.2.0"}}},
				{"tag_name": "v0.4.0", "draft": true, "assets": []map[string]string{{"name": "manifest.json", "browser_download_url": srv.URL + "/m/0.4.0"}}},
				{"tag_name": "v0.1.0", "draft": false, "assets": []map[string]string{{"name": "SHA256SUMS", "browser_download_url": srv.URL + "/x"}}},
				{"tag_name": "nightly", "draft": false},
			})
		case "/m/0.3.0", "/m/0.2.0", "/m/0.4.0":
			_ = json.NewEncoder(w).Encode(manifest(strings.TrimPrefix(r.URL.Path, "/m/")))
		default:
			w.WriteHeader(404)
		}
	}))
	return srv, &hits
}

func TestSyncImportsWhatABoxCanVerify(t *testing.T) {
	srv, hits := fakeGitHub(t)
	defer srv.Close()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := New(srv.URL+"/releases", st, nil)
	added, err := c.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(added, " ") != "0.3.0 0.2.0" {
		t.Fatalf("added %v", added)
	}
	rels, _ := st.Releases(context.Background())
	if len(rels) != 4 {
		t.Fatalf("stored %d releases, want 4 (two versions × two arches)", len(rels))
	}
	if rels[0].MinAgentVersion != "0.1.0" || rels[0].Signature == "" || !strings.HasPrefix(rels[0].URL, "https://github.com/") {
		t.Fatalf("release row: %+v", rels[0])
	}
	// second sync: nothing new, and the manifests are not fetched again
	before := *hits
	added, err = c.Sync(context.Background())
	if err != nil || len(added) != 0 {
		t.Fatalf("second sync: %v %v", added, err)
	}
	if *hits != before+1 {
		t.Fatalf("second sync should only fetch the list, got %d requests", *hits-before)
	}
	if s := c.Status(); s.LastError != "" || s.LastCheck.IsZero() || strings.Join(s.LastAdded, " ") != "0.3.0 0.2.0" {
		t.Fatalf("status %+v", s)
	}
}

func TestSyncReportsAnUnreachableCatalog(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	c := New("http://127.0.0.1:1/releases", st, nil)
	if _, err := c.Sync(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if s := c.Status(); s.LastError == "" {
		t.Fatal("status must carry the error")
	}
}

func TestValidateRefusesWhatABoxWouldRefuse(t *testing.T) {
	good := ManifestFile{OS: "linux", Arch: "amd64", Name: "x", URL: "https://h/x", SHA256: strings.Repeat("ab", 32), Signature: base64.StdEncoding.EncodeToString([]byte(strings.Repeat("s", 70)))}
	cases := map[string]Manifest{
		"version mismatch": {Version: "0.9.9", Files: []ManifestFile{good}},
		"no files":         {Version: "0.2.0"},
		"windows":          {Version: "0.2.0", Files: []ManifestFile{{OS: "windows", Arch: "amd64", URL: "https://h/x", SHA256: good.SHA256, Signature: good.Signature}}},
		"http url":         {Version: "0.2.0", Files: []ManifestFile{{OS: "linux", Arch: "amd64", URL: "http://h/x", SHA256: good.SHA256, Signature: good.Signature}}},
		"short sha":        {Version: "0.2.0", Files: []ManifestFile{{OS: "linux", Arch: "amd64", URL: "https://h/x", SHA256: "abcd", Signature: good.Signature}}},
		"short signature":  {Version: "0.2.0", Files: []ManifestFile{{OS: "linux", Arch: "amd64", URL: "https://h/x", SHA256: good.SHA256, Signature: "c2ln"}}},
	}
	for name, m := range cases {
		if err := validate("0.2.0", m); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := validate("0.2.0", Manifest{Version: "v0.2.0", Files: []ManifestFile{good}}); err != nil {
		t.Errorf("good manifest refused: %v", err)
	}
}
