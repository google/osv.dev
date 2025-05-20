package git

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport/client"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"golang.org/x/exp/maps"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

func TestRepoName(t *testing.T) {
	tests := []struct {
		description string
		input       string
		want        string
		expectedOk  bool
	}{
		// Fun fact: url.Parse() doesn't seem to reliably return errors...
		// {
		// 	description: "A totally bogus URL",
		// 	input:       "hkjfdshhkjgfdhjkgfd",
		// 	want:        "",
		// 	expectedOk:  false,
		// },
		{
			description: "A GitHub URL",
			input:       "https://github.com/eclipse-openj9/openj9",
			want:        "openj9",
			expectedOk:  true,
		},
		{
			description: "A cGit URL",
			input:       "https://git.libssh.org/projects/libssh.git",
			want:        "libssh",
			expectedOk:  true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := RepoName(tc.input)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: RepoName(%q) unexpectedly failed: %+v", tc.description, tc.input, err)
			}
			if got != tc.want {
				t.Errorf("test %q: RepoName(%q) unexpected result = %q, want %q", tc.description, tc.input, got, tc.want)
			}
		})
	}
}

func TestRepoTags(t *testing.T) {
	cache := make(RepoTagsCache)

	tests := []struct {
		description       string
		inputRepoURL      string
		cache             RepoTagsCache
		expectedResult    Tags
		expectedOk        bool
		disableExpiryDate time.Time
	}{
		{
			description:  "Repo with only lightweight tags and no caching",
			inputRepoURL: "https://github.com/zblogcn/zblogphp",
			cache:        nil,
			expectedResult: Tags{
				{Tag: "1.5.0.1525", Commit: "c8d47c25296ffda9f2083a813ed719b637f86c59"},
				{Tag: "1.5.0.1525-2", Commit: "fc4579cade51e0a565e5bd83503e028a17675e9d"},
				{Tag: "1.5.0.1525-3", Commit: "537c6000fe951d9e7719e204a4c324772ec28bcf"},
				{Tag: "1.5.0.1525-4", Commit: "3c9fdc49cc05d5a376a7f6fcd6e00390c9dc517f"},
				{Tag: "1.5.0.1525-5", Commit: "1a6b98c937288acf20a5e87e45b9f8e46e138da8"},
				{Tag: "1.5.0.1525-6", Commit: "21a2347cbf112eebe2fbc13e4b17d21ad946c7bf"},
				{Tag: "1.5.0.1525-7", Commit: "df6d05860a5b3ca46627f058c330d3bd72db80d1"},
				{Tag: "1.5.0.1525-8", Commit: "54434fe137f9c0c89889bfa7865c3b7b5e24e4b8"},
				{Tag: "1626", Commit: "45fc093f879348b855377d9ccf726403098ebe7d"},
				{Tag: "1740", Commit: "64eea82fc69906659382e7d1445df0081f202e51"},
				{Tag: "v1.6.0", Commit: "255cb7bf57134b3f32d237335f77892b94e1a43c"},
				{Tag: "v1.6.1", Commit: "2130805447e7819301ac53cc7323cadbebc82c58"},
				{Tag: "v1.7.0", Commit: "8474237fe952db369c318b989983aa59f6d11cde"},
				{Tag: "v1.7.0-2945", Commit: "8c6e4f2d3a2a79ce1822945dcbfdd1b7299b2aa1"},
				{Tag: "v1.7.0-beta", Commit: "08c5e0ac49c9520585eebfe25be0f51239733891"},
				{Tag: "v1.7.1-2960", Commit: "44b73602ab5518a213e0128a04f57239988847cf"},
				{Tag: "v1.7.2-3030", Commit: "302e57b5703d92d2f43bbfe86a8d4080647a4ba9"},
				{Tag: "v1.7.3-3230", Commit: "96a5fcdc3c958268559ec63c8fbd0a60e3c7e1c8"},
			},
			expectedOk: true,
		},
		{
			description:  "Repo with only lightweight tags and caching",
			inputRepoURL: "https://github.com/zblogcn/zblogphp",
			cache:        cache,
			expectedResult: Tags{
				{Tag: "1.5.0.1525", Commit: "c8d47c25296ffda9f2083a813ed719b637f86c59"},
				{Tag: "1.5.0.1525-2", Commit: "fc4579cade51e0a565e5bd83503e028a17675e9d"},
				{Tag: "1.5.0.1525-3", Commit: "537c6000fe951d9e7719e204a4c324772ec28bcf"},
				{Tag: "1.5.0.1525-4", Commit: "3c9fdc49cc05d5a376a7f6fcd6e00390c9dc517f"},
				{Tag: "1.5.0.1525-5", Commit: "1a6b98c937288acf20a5e87e45b9f8e46e138da8"},
				{Tag: "1.5.0.1525-6", Commit: "21a2347cbf112eebe2fbc13e4b17d21ad946c7bf"},
				{Tag: "1.5.0.1525-7", Commit: "df6d05860a5b3ca46627f058c330d3bd72db80d1"},
				{Tag: "1.5.0.1525-8", Commit: "54434fe137f9c0c89889bfa7865c3b7b5e24e4b8"},
				{Tag: "1626", Commit: "45fc093f879348b855377d9ccf726403098ebe7d"},
				{Tag: "1740", Commit: "64eea82fc69906659382e7d1445df0081f202e51"},
				{Tag: "v1.6.0", Commit: "255cb7bf57134b3f32d237335f77892b94e1a43c"},
				{Tag: "v1.6.1", Commit: "2130805447e7819301ac53cc7323cadbebc82c58"},
				{Tag: "v1.7.0", Commit: "8474237fe952db369c318b989983aa59f6d11cde"},
				{Tag: "v1.7.0-2945", Commit: "8c6e4f2d3a2a79ce1822945dcbfdd1b7299b2aa1"},
				{Tag: "v1.7.0-beta", Commit: "08c5e0ac49c9520585eebfe25be0f51239733891"},
				{Tag: "v1.7.1-2960", Commit: "44b73602ab5518a213e0128a04f57239988847cf"},
				{Tag: "v1.7.2-3030", Commit: "302e57b5703d92d2f43bbfe86a8d4080647a4ba9"},
				{Tag: "v1.7.3-3230", Commit: "96a5fcdc3c958268559ec63c8fbd0a60e3c7e1c8"},
			},
			expectedOk: true,
		},
		{
			description:  "Repo with lightweight and annotated tags and no caching",
			inputRepoURL: "https://github.com/andrewpollock/aide",
			cache:        nil,
			expectedResult: Tags{
				{Tag: "aide.0.10.release", Commit: "02961dda0a1f114802e107bad93108c9b9d092ed"},
				{Tag: "aide.0.11.rc1.release", Commit: "050147df2f788ce25787754df0d8c47b9fc743e0"},
				{Tag: "aide.0.11.rc2.release", Commit: "fd39909144f4a89d21748884610df2936ad2c46b"},
				{Tag: "aide.0.11.rc3.release", Commit: "09f4f761fb316364056966a5f9bb996e40eb2e1a"},
				{Tag: "aide.0.11.release", Commit: "3f4d262342256cc8eb6abebcb51520877140c476"},
				{Tag: "aide.0.11a.debian", Commit: "911e69815ed6a97f5a7fbc85713b8add4a45d8e7"},
				{Tag: "aide.0.11b.nocurl", Commit: "24d6d7c87e8e7bc6b15fdeb44dd025e7b8a959a4"},
				{Tag: "aide.0.12.rc1.release", Commit: "53949793c63618b565e9a5f6d1029b8cccebe9fb"},
				{Tag: "aide.0.12.rc2.release", Commit: "27f19a9d4d192abd65fd3e5e8108ced5d8ad0e14"},
				{Tag: "aide.0.12.release", Commit: "24f4794baa026f5e05768f4dc04629c22423f7fc"},
				{Tag: "aide.0.13.1.release", Commit: "117c3e7be1ed6db9a20196a044f0892c03d4655f"},
				{Tag: "aide.0.13.rc1.release", Commit: "cd162898b0344eb93945bd615586998b389f205c"},
				{Tag: "aide.0.13.rc2.release", Commit: "5e6a50d2c22b280770fc1b3c6fe3c1db75db74e8"},
				{Tag: "aide.0.13.release", Commit: "a43fa38b3665d9579da8dd21bf44b967ba3e6e20"},
				{Tag: "aide.0.14.1.release", Commit: "531ef22e7db3cadb1d9f67b1bf7a510e57cb7bd9"},
				{Tag: "aide.0.14.2.release", Commit: "585224a9a0af7ba0f7d127f09e477e46295ebb6d"},
				{Tag: "aide.0.14.rc1.release", Commit: "4e906d97488d30747a4d903a888ee88bc9af2086"},
				{Tag: "aide.0.14.rc2.release", Commit: "eaa4da81c202affa3000adca5757f2c9a5f81eeb"},
				{Tag: "aide.0.14.rc3.release", Commit: "e82be89f5e0036cc9d171d260e9c53713bb31b39"},
				{Tag: "aide.0.14.release", Commit: "727c5677d3c97d49e7b406eb3c3b51e6fc429f21"},
				{Tag: "aide.0.15.1.release", Commit: "3e41f1d1a96645fae661e3bd585d11a8bed0eb2e"},
				{Tag: "aide.0.15.rc1.release", Commit: "1b7d73f1b689e673bc0fac3f54005db0e0a0b4ab"},
				{Tag: "aide.0.15.release", Commit: "0d8f5df0e5d3f1047a286fab369ad02aafdc8857"},
				{Tag: "cs.tut.fi.import", Commit: "2e84254676a6148acd6ab8e7ce1cd9749836a445"},
				{Tag: "v0.16", Commit: "543c3f9f1af0414a52be20d35558f1490bcf559b"},
				{Tag: "v0.16.1", Commit: "62cf11b455279f2fa4dcc7755f6145b48c1db0a4"},
				{Tag: "v0.16.2", Commit: "a8a5d67f4abb230df850f7b327b1f373e7ec49cf"},
				{Tag: "v0.16a1", Commit: "c52f1ca1d4d204ffef05c71e46a0b4195940fd79"},
				{Tag: "v0.16a2", Commit: "7a460b9191c981134381b965798984580838c2c8"},
				{Tag: "v0.16b1", Commit: "6be695a9b8b3b64a0d3d2f9a0c92e027f4c462f8"},
				{Tag: "v0.16rc1", Commit: "7bf821b14d24711f559a8b213f68a5dfefe6345b"},
				{Tag: "v0.17", Commit: "fcca55970940387efaccdfefd870fd9f4c958c9e"},
				{Tag: "v0.17.1", Commit: "98322b8a6e00c189e4f9226269dd9d03c04ad610"},
				{Tag: "v0.17.2", Commit: "35927ea48d3e43a146103733c6459dd66237f4dd"},
				{Tag: "v0.17.3", Commit: "d4b80a9e5d48494e0003d22d9ce1a8133de0f15e"},
				{Tag: "v0.17.4", Commit: "f57bbfdd5dad88187913a39c360cf1dd69c28819"},
				{Tag: "v0.18", Commit: "73078765396b99ac1ce9004d35a1ee5db2fbb6e5"},
				{Tag: "v0.18.1", Commit: "de5bb24b9b24df7598161a1ce19dc2ce15afa9c6"},
				{Tag: "v0.18.2", Commit: "3d5b18b9e5e1c51533ac01d8acd3499b2f9fcc2e"},
				{Tag: "v0.18.3", Commit: "1cf7764293aebb473baee3ff82298d83593943e8"},
				{Tag: "v0.18.4", Commit: "c03255688a13cf7089eeb7a292c1de2abf1d3a9d"},
				{Tag: "v0.18.5", Commit: "a164c35a217579b1eec3b548f9421cd030160c5b"},
				{Tag: "v0.18.6", Commit: "82fd64038788942aef8a394d6d4b802cb529f71b"},
			},
			expectedOk: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			// Cannot make this test parallel because it modifies the global git protocols.
			r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Stop(); err != nil {
					t.Error(err)
				}
			})
			httpClient := r.GetDefaultClient()
			client.InstallProtocol("http", githttp.NewClient(httpClient))
			client.InstallProtocol("https", githttp.NewClient(httpClient))
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: TestRepoTags(%q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputRepoURL, tc.disableExpiryDate)
			}
			var cache_before, cache_after int
			if tc.cache != nil {
				cache_before = len(tc.cache)
			}
			got, err := RepoTags(tc.inputRepoURL, tc.cache)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: RepoTags(%q) unexpectedly failed: %+v", tc.description, tc.inputRepoURL, err)
			}
			if diff := cmp.Diff(got, tc.expectedResult); diff != "" {
				t.Errorf("test %q: RepoTags(%q) incorrect result: %s", tc.description, tc.inputRepoURL, diff)
			}
			if tc.cache != nil {
				cache_after = len(tc.cache)
			}
			if tc.cache != nil && !(cache_after > cache_before) {
				t.Errorf("test %q: RepoTags(%q) incorrect cache behaviour: size before: %d size after: %d cache: %#v", tc.description, tc.inputRepoURL, cache_before, cache_after, tc.cache)
			}
		})
	}
}

func TestNormalizeRepoTag(t *testing.T) {
	tests := []struct {
		description    string
		inputTag       string
		repoName       string
		expectedResult string
		expectedOk     bool
	}{
		{
			description:    "A tag that is perfectly fine just the way it is",
			inputTag:       "1.2.3",
			repoName:       "acme",
			expectedResult: "1-2-3",
			expectedOk:     true,
		},
		{
			description:    "A tag with a reponame prepended",
			inputTag:       "acme-2000",
			repoName:       "acme",
			expectedResult: "2000",
			expectedOk:     true,
		},
		{
			description:    "A tag with a reponame containing a number prepended",
			inputTag:       "yui2-2000",
			repoName:       "yui2",
			expectedResult: "2000",
			expectedOk:     true,
		},
		{
			description:    "A tag with a reponame containing a number in the middle",
			inputTag:       "hudson-yui2-2800",
			repoName:       "yui2",
			expectedResult: "2800",
			expectedOk:     true,
		},
		{
			description:    "A tag with a Java package name prefix",
			inputTag:       "org.apache.sling.i18n-2.0.2",
			repoName:       "sling-org-apache-sling-i18n",
			expectedResult: "2-0-2",
			expectedOk:     true,
		},
		{
			description:    "A tag with a v prefix",
			inputTag:       "v0.0.245",
			repoName:       "langchain",
			expectedResult: "0-0-245",
			expectedOk:     true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			t.Parallel()
			got, err := normalizeRepoTag(tc.inputTag, tc.repoName)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: normalizeRepoTag(%q, %q): %q unexpectedly failed: %+v", tc.description, tc.inputTag, tc.repoName, got, err)
			}
			if diff := cmp.Diff(got, tc.expectedResult); diff != "" {
				t.Errorf("test %q: normalizeRepoTag(%q, %q) incorrect result: %s", tc.description, tc.inputTag, tc.repoName, diff)
			}
		})
	}
}

func TestNormalizeRepoTags(t *testing.T) {
	tests := []struct {
		description       string
		inputRepoURL      string
		expectedOk        bool
		disableExpiryDate time.Time
	}{
		{
			description:  "Valid repository, normalized versions exist",
			inputRepoURL: "https://github.com/aide/aide",
			expectedOk:   true,
		},
		{
			description:  "Valid repository, edge-case normalized versions exist",
			inputRepoURL: "https://github.com/eclipse-openj9/openj9",
			expectedOk:   true,
		},
		{
			description:  "Valid repository, no tags, normalized versions do not exist",
			inputRepoURL: "https://github.com/andrewpollock/osv.dev.git",
			expectedOk:   false,
		},
		{
			description:  "Invalid repository",
			inputRepoURL: "https://github.com/andrewpollock/mybogusrepo",
			expectedOk:   false,
		},
	}
	cache := make(RepoTagsCache)
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			// Cannot make this test parallel because it modifies the global git protocols.
			r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Stop(); err != nil {
					t.Error(err)
				}
			})
			httpClient := r.GetDefaultClient()
			client.InstallProtocol("http", githttp.NewClient(httpClient))
			client.InstallProtocol("https", githttp.NewClient(httpClient))

			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: TestNormalizeRepoTags(%q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.inputRepoURL, tc.disableExpiryDate)
			}
			normalizedRepoTags, err := NormalizeRepoTags(tc.inputRepoURL, cache)
			if err != nil && tc.expectedOk {
				t.Errorf("test %q: NormalizeRepoTags(%q) unexpectedly failed: %+v", tc.description, tc.inputRepoURL, err)
			}
			// Confirm there are some normalized versions
			if len(maps.Keys(normalizedRepoTags)) == 0 && tc.expectedOk {
				t.Errorf("test %q: NormalizeRepoTags(%q): failed to find any normalized versions for repo in map: %#v", tc.description, tc.inputRepoURL, normalizedRepoTags)
			}
			if len(maps.Keys(normalizedRepoTags)) > 0 && cache[tc.inputRepoURL].NormalizedTag == nil {
				t.Errorf("test %q: NormalizeRepoTags(%q) incorrect cache behaviour: %#v", tc.description, tc.inputRepoURL, cache)
			}
			t.Logf("test %q: NormalizedRepoTags(%q): %#v", tc.description, tc.inputRepoURL, normalizedRepoTags)
		})
	}
}

func TestValidRepo(t *testing.T) {
	tests := []struct {
		description       string
		repoURL           string
		expectedResult    interface{}
		expectedOk        bool
		disableExpiryDate time.Time
	}{
		{
			description:    "Valid repository",
			repoURL:        "https://github.com/torvalds/linux",
			expectedResult: true,
		},
		{
			description: "Valid repository with a git:// protocol URL",
			// Note: git:// protocol cannot go through go-vcr - this will connect to internet
			repoURL:        "git://git.infradead.org/mtd-utils.git",
			expectedResult: true,
		},
		{
			description:    "Invalid repository",
			repoURL:        "https://github.com/andrewpollock/mybogusrepo",
			expectedResult: false,
		},
		{
			description:    "Legitimate repository with no tags and two branches",
			repoURL:        "https://github.com/202ecommerce/security-advisories",
			expectedResult: false,
		},
		{
			description:    "Legitimate repository with no tags and one branch",
			repoURL:        "https://github.com/active-labs/Advisories",
			expectedResult: false,
		},
		{
			description:    "Unusable repo that seems to be slipping past",
			repoURL:        "https://github.com/shaturo1337/POCs",
			expectedResult: false,
		},
		{
			description:    "Unusable repo (without remapping) that seems to be slipping past",
			repoURL:        "https://git.musl-libc.org/cgit/musl",
			expectedResult: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.description, func(t *testing.T) {
			// Cannot make this test parallel because it modifies the global git protocols.
			r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := r.Stop(); err != nil {
					t.Error(err)
				}
			})
			httpClient := r.GetDefaultClient()
			client.InstallProtocol("http", githttp.NewClient(httpClient))
			client.InstallProtocol("https", githttp.NewClient(httpClient))
			// This tests against Internet hosts and may have intermittent failures.
			if time.Now().Before(tc.disableExpiryDate) {
				t.Skipf("test %q: TestValidRepo(%q) has been skipped due to known outage and will be reenabled on %s.", tc.description, tc.repoURL, tc.disableExpiryDate)
			}
			got := ValidRepoAndHasUsableRefs(tc.repoURL)
			if diff := cmp.Diff(got, tc.expectedResult); diff != "" {
				t.Errorf("test %q: ValidRepo(%q) was incorrect: %s", tc.description, tc.repoURL, diff)
				t.Logf("Confirm that %s is reachable with `git ls-remote %s`", tc.repoURL, tc.repoURL)
			}
		})
	}
}

func TestInvalidRepos(t *testing.T) {
	// Cannot make this test parallel because it modifies the global git protocols.
	r, err := recorder.New(filepath.Join("testdata", strings.ReplaceAll(t.Name(), "/", "_")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := r.Stop(); err != nil {
			t.Error(err)
		}
	})
	httpClient := r.GetDefaultClient()
	client.InstallProtocol("http", githttp.NewClient(httpClient))
	client.InstallProtocol("https", githttp.NewClient(httpClient))

	redundantRepos := []string{}
	for _, repo := range cves.InvalidRepos {
		if !ValidRepoAndHasUsableRefs(repo) {
			redundantRepos = append(redundantRepos, repo)
		}
	}
	if diff := cmp.Diff([]string{}, redundantRepos); diff != "" {
		t.Errorf("These redundant repos are in InvalidRepos: %s", diff)
	}
}
