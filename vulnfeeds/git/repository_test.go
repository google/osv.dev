package git

import (
	"reflect"
	"testing"

	"github.com/go-test/deep"
)

func TestRepoTags(t *testing.T) {
	var cache *RepoTagsMap

	tests := []struct {
		description    string
		inputRepoURL   string
		cache          *RepoTagsMap
		expectedResult Versions
		expectedOk     bool
	}{
		{
			description:  "Repo with only lightweight tags and no cacheing",
			inputRepoURL: "https://github.com/zblogcn/zblogphp",
			cache:        nil,
			expectedResult: Versions{
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
			},
			expectedOk: true,
		},
		{
			description:  "Repo with only lightweight tags and cacheing",
			inputRepoURL: "https://github.com/zblogcn/zblogphp",
			cache:        cache,
			expectedResult: Versions{
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
			},
			expectedOk: true,
		},
		{
			description:  "Repo with lightweight and annotated tags and no cacheing",
			inputRepoURL: "https://github.com/aide/aide",
			cache:        nil,
			expectedResult: Versions{
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
				{Tag: "aide.0.15.1.release", Commit: "213165495c7cc7209b3aea786ea07e0501045d25"},
				{Tag: "aide.0.15.rc1.release", Commit: "6e639e18f79ca840673709738fe2b5b7ba842980"},
				{Tag: "aide.0.15.release", Commit: "95995531cdd9ce0cd043a3f48431ed1751f46cfc"},
				{Tag: "cs.tut.fi.import", Commit: "2e84254676a6148acd6ab8e7ce1cd9749836a445"},
				{Tag: "v0.16", Commit: "3730e8f503d94aa29f0128158e7c46986ec227cf"},
				{Tag: "v0.16.1", Commit: "63331d10348428ae30a378a9399eaa6185de8ef2"},
				{Tag: "v0.16.2", Commit: "463797d6164997f746b472f451e9cb4bbebf3a05"},
				{Tag: "v0.16a1", Commit: "25e59edc12a3f8c19745eae04d77a94eb61207db"},
				{Tag: "v0.16a2", Commit: "121fbe3633b586e0bd91bb7eaa4fecd4dd1b63ba"},
				{Tag: "v0.16b1", Commit: "e0763affa46f85ab1d8b7ad88a876cf86dc813f7"},
				{Tag: "v0.16rc1", Commit: "6de8660468429bcdc35d56597aeaa307033d127c"},
				{Tag: "v0.17", Commit: "33c436580b35e83929e65d069e6ba138339f6cd7"},
				{Tag: "v0.17.1", Commit: "920fd575144f247439f64debad4400240cefbd4a"},
				{Tag: "v0.17.2", Commit: "4a3cbc9e25c63402f98172206b8492e34c733dd5"},
				{Tag: "v0.17.3", Commit: "b1fda5bdd5e74ab7874f5c93fecb35457cc68f78"},
				{Tag: "v0.17.4", Commit: "49e8faad5e2ed9ab2de54f6858ee223f918abac4"},
				{Tag: "v0.18", Commit: "8ed48ad5ba180cd3ce30a3c41d42bad3779d9f26"},
			},
			expectedOk: true,
		},
	}

	for _, tc := range tests {
		var cache_before, cache_after int
		if tc.cache != nil {
			cache_before = len(*cache)
		}
		got, err := RepoTags(tc.inputRepoURL, tc.cache)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: RepoTags(%q) unexpectedly failed: %+v", tc.description, tc.inputRepoURL, err)
		}
		if diff := deep.Equal(got, tc.expectedResult); diff != nil {
			t.Errorf("test %q: RepoTags(%q) incorrect result: %#v", tc.description, tc.inputRepoURL, diff)
			// t.Errorf("test %q: RepoTags(%q) incorrect result: expected: %#v, got: %#v", tc.description, tc.inputRepoURL, tc.expectedResult, got)
		}
		if tc.cache != nil {
			cache_after = len(*cache)
		}
		if tc.cache != nil && !(cache_after > cache_before) {
			t.Errorf("test %q: RepoTags(%q) incorrect cache behaviour: size before: %d size after: %d", tc.description, tc.inputRepoURL, cache_before, cache_after)
		}
	}
}

func TestValidRepo(t *testing.T) {
	tests := []struct {
		description    string
		repoURL        string
		expectedResult interface{}
		expectedOk     bool
	}{
		{
			description:    "Valid repository",
			repoURL:        "https://github.com/torvalds/linux",
			expectedResult: true,
			expectedOk:     true,
		},
		{
			description:    "Invalid repository",
			repoURL:        "https://github.com/andrewpollock/mybogusrepo",
			expectedResult: false,
			expectedOk:     true,
		},
	}
	for _, tc := range tests {
		got, err := ValidRepo(tc.repoURL)
		if err != nil && tc.expectedOk {
			t.Errorf("test %q: ValidRepo(%q) unexpectedly failed: %#v", tc.description, tc.repoURL, err)
		}
		if !reflect.DeepEqual(got, tc.expectedResult) {
			t.Errorf("test %q: ValidRepo(%q) was incorrect, got: %#v, expected: %#v", tc.description, tc.repoURL, got, tc.expectedResult)
		}
	}
}
