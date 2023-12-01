// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cves

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/sethvargo/go-retry"
	"golang.org/x/exp/slices"
)

type AffectedCommit struct {
	Repo         string `json:"repo,omitempty" yaml:"repo,omitempty"`
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	Limit        string `json:"limit,omitempty" yaml:"limit,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

func (ac *AffectedCommit) SetRepo(repo string) {
	ac.Repo = repo
}

func (ac *AffectedCommit) SetIntroduced(commit string) {
	ac.Introduced = commit
}

func (ac *AffectedCommit) SetFixed(commit string) {
	ac.Fixed = commit
}

func (ac *AffectedCommit) SetLimit(commit string) {
	ac.Limit = commit
}

func (ac *AffectedCommit) SetLastAffected(commit string) {
	ac.LastAffected = commit
}

type AffectedVersion struct {
	Introduced   string `json:"introduced,omitempty" yaml:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty" yaml:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty" yaml:"last_affected,omitempty"`
}

type VersionInfo struct {
	AffectedCommits  []AffectedCommit  `json:"affect_commits,omitempty" yaml:"affected_commits,omitempty"`
	AffectedVersions []AffectedVersion `json:"affected_versions,omitempty" yaml:"affected_versions,omitempty"`
}

func (vi *VersionInfo) HasFixedVersions() bool {
	for _, av := range vi.AffectedVersions {
		if av.Fixed != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasLastAffectedVersions() bool {
	for _, av := range vi.AffectedVersions {
		if av.LastAffected != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasIntroducedCommits(repo string) bool {
	for _, av := range vi.AffectedCommits {
		if av.Repo == repo && av.Introduced != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasFixedCommits(repo string) bool {
	for _, av := range vi.AffectedCommits {
		if av.Repo == repo && av.Fixed != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) HasLastAffectedCommits(repo string) bool {
	for _, av := range vi.AffectedCommits {
		if av.Repo == repo && av.LastAffected != "" {
			return true
		}
	}
	return false
}

func (vi *VersionInfo) FixedCommits(repo string) (FixedCommits []string) {
	for _, av := range vi.AffectedCommits {
		if av.Repo == repo && av.Fixed != "" {
			FixedCommits = append(FixedCommits, av.Fixed)
		}
	}
	return FixedCommits
}

func (vi *VersionInfo) LastAffectedCommits(repo string) (LastAffectedCommits []string) {
	for _, av := range vi.AffectedCommits {
		if av.Repo == repo && av.LastAffected != "" {
			LastAffectedCommits = append(LastAffectedCommits, av.Fixed)
		}
	}
	return LastAffectedCommits
}

// Synthetic enum of supported commit types.
type CommitType int

const (
	Introduced CommitType = iota
	Fixed
	Limit
	LastAffected
)

type CPE struct {
	CPEVersion string
	Part       string
	Vendor     string
	Product    string
	Version    string
	Update     string
	Edition    string
	Language   string
	SWEdition  string
	TargetSW   string
	TargetHW   string
	Other      string
}

var (
	// TODO(apollock): read this from an external file
	InvalidRepos = []string{
		"https://github.com/0day1/g1ory",
		"https://github.com/0x14dli/ffos-SQL-injection-vulnerability-exists",
		"https://github.com/0x72303074/cve-disclosures",
		"https://github.com/0xdea/exploits",
		"https://github.com/0xxtoby/Vuldb",
		"https://github.com/10cks/inkdropPoc",
		"https://github.com/10cksyiqiyinhangzhoutechnology/elf-parser_segments_poc",
		"https://github.com/1MurasaKi/Eyewear_Shop_XSS",
		"https://github.com/1MurasaKi/PizzeXSS_Report",
		"https://github.com/1MurasaKi/STMS_CSRF",
		"https://github.com/1security/Vulnerability",
		"https://github.com/202ecommerce/security-advisories",
		"https://github.com/abhiunix/goo-blog-App-CVE",
		"https://github.com/Accenture/AARO-Bugs",
		"https://github.com/active-labs/Advisories",
		"https://github.com/ae6e361b/online-job-portal-forget",
		"https://github.com/afeng2016-s/CVE-Request",
		"https://github.com/agadient/SERVEEZ-CVE",
		"https://github.com/Airrudder/vuls",
		"https://github.com/AlwaysHereFight/YZMCMSxss",
		"https://github.com/alwentiu/COVIDSafe-CVE-2020-12856",
		"https://github.com/anhdq201/rukovoditel",
		"https://github.com/anhdq201/webtareas",
		"https://github.com/anvilsecure/garmin-ciq-app-research",
		"https://github.com/anx0ing/CVE_demo",
		"https://github.com/Anza2001/IOT_VULN",
		"https://github.com/apriorit/pentesting",
		"https://github.com/ArianeBlow/Axelor_Stored_XSS",
		"https://github.com/As4ki/CVE-report",
		"https://github.com/A-TGAO/MxsDocVul",
		"https://github.com/atredispartners/advisories",
		"https://github.com/awillix/research",
		"https://github.com/b17fr13nds/MPlayer_cve_poc",
		"https://github.com/badboycxcc/Student-Admission-Sqlinjection",
		"https://github.com/badboycxcc/Student-Admission-Xss",
		"https://github.com/beicheng-maker/vulns",
		"https://github.com/benjaminpsinclair/netdisco-2023-advisory",
		"https://github.com/BigTiger2020/2022",
		"https://github.com/BigTiger2020/2023-1",
		"https://github.com/BigTiger2020/74CMS",
		"https://github.com/BigTiger2020/Fantastic-Blog-CMS-",
		"https://github.com/BigTiger2020/Theme-Park-Ticketing-System",
		"https://github.com/BigTiger2020/UCMS",
		"https://github.com/BlackFan/client-side-prototype-pollution",
		"https://github.com/blindkey/cve_like",
		"https://github.com/BLL-l/vulnerability_wiki",
		"https://github.com/blockomat2100/PoCs",
		"https://github.com/bosslabdcu/Vulnerability-Reporting",
		"https://github.com/ByteHackr/unzip_poc",
		"https://github.com/capgeminicisredteam/disclosure",
		"https://github.com/CapgeminiCisRedTeam/Disclosure",
		"https://github.com/Castle1984/CveRecord",
		"https://github.com/ch0ing/vul",
		"https://github.com/Ch0pin/security-advisories",
		"https://github.com/chenan224/webchess_sqli_poc",
		"https://github.com/Chu1z1/Chuizi",
		"https://github.com/ciph0x01/poc",
		"https://github.com/ciph0x01/Simple-Exam-Reviewer-Management-System-CVE",
		"https://github.com/cloudflare/advisories",
		"https://github.com/Coalfire-Research/WinAPRS-Exploits",
		"https://github.com/ComparedArray/printix-CVE-2022-25089",
		"https://github.com/cribdragg3r/offensive_research",
		"https://github.com/ctflearner/Vulnerability",
		"https://github.com/CVEProject/cvelist", // Heavily in Advisory URLs, sometimes shows up elsewhere
		"https://github.com/cve-vul/vul",
		"https://github.com/Cvjark/Poc",
		"https://github.com/cxaqhq/Loan-Management-System-Sqlinjection",
		"https://github.com/cyb3r-n3rd/cve-request",
		"https://github.com/cybersecurityworks/disclosed",
		"https://github.com/D4rkP0w4r/AeroCMS-Add_Posts-Stored_XSS-Poc",
		"https://github.com/D4rkP0w4r/AeroCMS-Comment-Stored_XSS-Poc",
		"https://github.com/D4rkP0w4r/AeroCMS-Unrestricted-File-Upload-POC",
		"https://github.com/D4rkP0w4r/Full-Ecommece-Website-Add_Product-Unrestricted-File-Upload-RCE-POC",
		"https://github.com/D4rkP0w4r/Full-Ecommece-Website-Add_User-Stored-XSS-POC",
		"https://github.com/D4rkP0w4r/Full-Ecommece-Website-Slides-Unrestricted-File-Upload-RCE-POC",
		"https://github.com/D4rkP0w4r/sms-Add_Student-Stored_XSS-POC",
		"https://github.com/D4rkP0w4r/sms-Unrestricted-File-Upload-RCE-POC",
		"https://github.com/daaaalllii/cve-s",
		"https://github.com/DayiliWaseem/CVE-2022-39196-",
		"https://github.com/dhammon/pfBlockerNg-CVE-2022-40624",
		"https://github.com/dhammon/pfBlockerNg-RCE",
		"https://github.com/Dheeraj-Deshmukh/Hospital-s-patient-management-system",
		"https://github.com/Dheeraj-Deshmukh/stored-xss-in-Hospital-s-Patient-Records-Management-System",
		"https://github.com/digitemis/advisory",
		"https://github.com/DiliLearngent/BugReport",
		"https://github.com/Dir0x/Multiple-SQLi-in-Simple-Subscription-Company",
		"https://github.com/Dir0x/SQLi-exploit---Simple-Client-Management-System",
		"https://github.com/DisguisedRoot/Exploit",
		"https://github.com/dodge-mptc/cve-2023-35793-csrf-on-web-ssh",
		"https://github.com/Don-H50/wp-vul",
		"https://github.com/dota-st/Vulnerability",
		"https://github.com/draco1725/POC",
		"https://github.com/draco1725/Stored-XSS",
		"https://github.com/Drun1baby/CVE_Pentest",
		"https://github.com/dtssec/CVE-Disclosures",
		"https://github.com/Durian1546/vul",
		"https://github.com/Dyrandy/BugBounty",
		"https://github.com/E1CHO/cve_hub",
		"https://github.com/E1CHO/water_cve",
		"https://github.com/eddietcc/CVEnotes",
		"https://github.com/Edubr2020/RealPlayer_G2_RCE",
		"https://github.com/Edubr2020/RP_DCP_Code_Exec",
		"https://github.com/Edubr2020/RP_Import_RCE",
		"https://github.com/enesozeser/Vulnerabilities",
		"https://github.com/Ephemeral1y/Vulnerability",
		"https://github.com/erengozaydin/College-Management-System-course_code-SQL-Injection-Authenticated",
		"https://github.com/erengozaydin/Microfinance-Management-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated",
		"https://github.com/erengozaydin/Royal-Event-Management-System-todate-SQL-Injection-Authenticated",
		"https://github.com/esp0xdeadbeef/rce_webmin",
		"https://github.com/etn0tw/cmscve_test",
		"https://github.com/f4cky0u/security-vulnerabilities",
		"https://github.com/Fadavvi/CVE-2018-17431-PoC",
		"https://github.com/FCncdn/Appsmith-Js-Injection-POC",
		"https://github.com/Filiplain/LFI-to-RCE-SE-Suite-2.0",
		"https://github.com/fireeye/Vulnerability-Disclosures",
		"https://github.com/frame84/vulns",
		"https://github.com/Frank-Z7/z-vulnerabilitys",
		"https://github.com/FusionAuth/fusionauth-issues",
		"https://github.com/gdianq/Gym-Management-Exercises-Sqlinjection",
		"https://github.com/gdianq/Gym-Management-System-loginpage-Sqlinjection",
		"https://github.com/gdianq/Gym-Management-System-Sqlinjection",
		"https://github.com/gdianq/Sparkz-Hotel-Management-loginpage-Sqlinjection",
		"https://github.com/github/cvelist", // Fork of https://github.com/CVEProject/cvelist
		"https://github.com/github/securitylab",
		"https://github.com/gitlabhq/gitlabhq",     // GitHub mirror, not canonical
		"https://github.com/google/oss-fuzz-vulns", // 8^)
		"https://github.com/gou-web/Parking-management-systemXSS-",
		"https://github.com/Gr4y21/My-CVE-IDs",
		"https://github.com/grafana/bugbounty",
		"https://github.com/guyinatuxedo/sqlite3_record_leaking",
		"https://github.com/GZRsecurity/Cve-System",
		"https://github.com/h4md153v63n/CVE-2022-40032_Simple-Task-Managing-System-V1.0-SQL-Injection-Vulnerability-Unauthenticated",
		"https://github.com/h4md153v63n/CVE-2022-40347_Intern-Record-System-phone-V1.0-SQL-Injection-Vulnerability-Unauthenticated",
		"https://github.com/h4md153v63n/CVE-2022-40348_Intern-Record-System-Cross-site-Scripting-V1.0-Vulnerability-Unauthenticated",
		"https://github.com/H4rk3nz0/PenTesting",
		"https://github.com/Ha0Liu/cveAdd",
		"https://github.com/hackerzyq/mycve",
		"https://github.com/Hakcoder/Simple-Online-Public-Access-Catalog-OPAC---SQL-injection",
		"https://github.com/Hanfu-l/Cve-vulnerability-mining",
		"https://github.com/Hanfu-l/POC-Exp",
		"https://github.com/Hanwengao/CVERequests",
		"https://github.com/hashicorp/terraform-enterprise-release-notes",
		"https://github.com/haxpunk1337/Enterprise-Survey-Software",
		"https://github.com/haxpunk1337/MDaemon-",
		"https://github.com/hemantsolo/CVE-Reference",
		"https://github.com/HH1F/KbaseDoc-v1.0-Arbitrary-file-deletion-vulnerability",
		"https://github.com/hkerma/opa-gatekeeper-concurrency-issue",
		"https://github.com/hmsec/advisories",
		"https://github.com/hnsecurity/vulns",
		"https://github.com/hotencode/CveHub",
		"https://github.com/hubenlab/hubenvullist",
		"https://github.com/huclilu/CVE_Add",
		"https://github.com/Hyperkopite/Roothub_vulns",
		"https://github.com/i3umi3iei3ii/CentOS-Control-Web-Panel-CVE",
		"https://github.com/ianxtianxt/gitbook-xss",
		"https://github.com/imsebao/404team",
		"https://github.com/InfoSecWarrior/Offensive-Payloads",
		"https://github.com/IthacaLabs/DevExpress",
		"https://github.com/IthacaLabs/Parallels",
		"https://github.com/IthacaLabs/Vsourz-Digital",
		"https://github.com/itodaro/doorGets_cve",
		"https://github.com/JackyG0/Online-Accreditation-Management-System-v1.0-SQLi",
		"https://github.com/jacky-y/vuls",
		"https://github.com/Jamison2022/Company-Website-CMS",
		"https://github.com/Jamison2022/Wedding-Hall-Booking-System",
		"https://github.com/jcarabantes/Bus-Vulnerabilities",
		"https://github.com/jingping911/exshopbug",
		"https://github.com/jiy2020/bugReport",
		"https://github.com/jlleitschuh/security-research",
		"https://github.com/joinia/webray.com.cn",
		"https://github.com/JunyanYip/itsourcecode_justines_xss_vul",
		"https://github.com/jusstSahil/CSRF-",
		"https://github.com/jvz/test-cvelist",
		"https://github.com/k0xx11/Vulscve",
		"https://github.com/k0xx11/vul-wiki",
		"https://github.com/kaoudis/advisories",
		"https://github.com/Kenun99/CVE-batdappboomx",
		"https://github.com/Keyvanhardani/Exploit-eShop-Multipurpose-Ecommerce-Store-Website-3.0.4-Cross-Site-Scripting-XSS",
		"https://github.com/killmonday/isic.lk-RCE",
		"https://github.com/KingBridgeSS/Online_Driving_School_Project_In_PHP_With_Source_Code_Vulnerabilities",
		"https://github.com/kirra-max/bug_reports",
		"https://github.com/Kitsun3Sec/exploits",
		"https://github.com/kk98kk0/exploit",
		"https://github.com/KLSEHB/vulnerability-report",
		"https://github.com/kmkz/exploit",
		"https://github.com/kyrie403/Vuln",
		"https://github.com/L1917/Fast-Food-Ordering-System",
		"https://github.com/l1nk3rlin/php_code_audit_project",
		"https://github.com/lakshaya0557/POCs",
		"https://github.com/laotun-s/POC",
		"https://github.com/leekenghwa/CVE-2023-33817---SQL-Injection-found-in-HotelDruid-3.0.5",
		"https://github.com/leekenghwa/CVE-2023-34830---Reflected-XSS-found-in-I-doit-Open-v24-and-below",
		"https://github.com/Lemon4044/Fast-Food-Ordering-System",
		"https://github.com/LeozhangCA/CVEReport",
		"https://github.com/lohyt/Persistent-Cross-Site-Scripting-found-in-Online-Jewellery-Store-from-Sourcecodester-website.",
		"https://github.com/lohyt/web-shell-via-file-upload-in-hocms",
		"https://github.com/luelueking/ruoyi-4.7.5-vuln-poc",
		"https://github.com/lukaszstu/SmartAsset-CORS-CVE-2020-26527",
		"https://github.com/ly1g3/Mailcow-CVE-2022-31138",
		"https://github.com/M9KJ-TEAM/CVEReport",
		"https://github.com/MacherCS/CVE_Evoh_Contract",
		"https://github.com/MaherAzzouzi/CVE-2022-37706-LPE-exploit",
		"https://github.com/mandiant/Vulnerability-Disclosures",
		"https://github.com/martinkubecka/CVE-References",
		"https://github.com/Matrix07ksa/ALLMediaServer-1.6-Buffer-Overflow",
		"https://github.com/mclab-hbrs/BBB-POC",
		"https://github.com/metaredteam/external-disclosures",
		"https://github.com/metaStor/Vuls",
		"https://github.com/mikeccltt/0525",
		"https://github.com/mikeccltt/0724",
		"https://github.com/mikeccltt/automotive",
		"https://github.com/mikeccltt/badminton-center-management-system",
		"https://github.com/mikeccltt/bug_report_CVE",
		"https://github.com/mikeccltt/chatbot",
		"https://github.com/mikeccltt/wbms_bug_report",
		"https://github.com/mikeisastar/counter-strike-arbitrary-file-read",
		"https://github.com/Mirantis/security",
		"https://github.com/mirchr/security-research",
		"https://github.com/MiserablefaithL/CVERequestReport",
		"https://github.com/mrojz/rconfig-exploit",
		"https://github.com/MrR3boot/CVE-Hunting",
		"https://github.com/Mr-Secure-Code/My-CVE",
		"https://github.com/MrTuxracer/advisories",
		"https://github.com/mudassiruddin/CVE-2022-43144-Stored-XSS",
		"https://github.com/N1ce759/74cmsSE-Arbitrary-File-Reading",
		"https://github.com/nam3lum/msi-central_privesc",
		"https://github.com/navaidzansari/cve_demo",
		"https://github.com/navaidzansari/CVE_Demo",
		"https://github.com/nepenthe0320/cve_poc",
		"https://github.com/Netflix/security-bulletins",
		"https://github.com/nextcloud/security-advisories",
		"https://github.com/nikip72/CVE-2021-39273-CVE-2021-39274",
		"https://github.com/novysodope/vulreq",
		"https://github.com/nsparker1337/OpenSource",
		"https://github.com/nu11secur1ty/CVE-nu11secur1ty",
		"https://github.com/offsecin/bugsdisclose",
		"https://github.com/orangecertcc/security-research",
		"https://github.com/Orange-Cyberdefense/CVE-repository",
		"https://github.com/oV201/cve_report",
		"https://github.com/Ozozuz/Qlik-View-Stored-XSS",
		"https://github.com/p0dalirius/CVE-2022-26159-Ametys-Autocompletion-XML",
		"https://github.com/PabloMK7/ENLBufferPwn",
		"https://github.com/palantir/security-bulletins",
		"https://github.com/passtheticket/vulnerability-research",
		"https://github.com/Peanut886/Vulnerability",
		"https://github.com/piuppi/proof-of-concepts",
		"https://github.com/playZG/Exploit-",
		"https://github.com/PostalBlab/Vulnerabilities",
		"https://github.com/post-cyberlabs/CVE-Advisory",
		"https://github.com/prismbreak/vulnerabilities",
		"https://github.com/purplededa/EasyoneCRM-5.50.02-SQLinjection",
		"https://github.com/PurplePetrus/MxCC_Credential-Storage_issue",
		"https://github.com/Q2Flc2FySec/CVE-List",
		"https://github.com/qwegz/CveList",
		"https://github.com/qyhmsys/cve-list",
		"https://github.com/Ramansh123454/POCs",
		"https://github.com/rand0midas/randomideas",
		"https://github.com/raozhir/CVERequest",
		"https://github.com/rapid7/metasploit-framework",
		"https://github.com/refi64/CVE-2020-25265-25266",
		"https://github.com/riteshgohil/My_CVE_References",
		"https://github.com/rohit0x5/poc",
		"https://github.com/roughb8722/CVE-2021-3122-Details",
		"https://github.com/rsrahulsingh05/POC",
		"https://github.com/rtcrowley/poc",
		"https://github.com/rumble773/sec-research",
		"https://github.com/RupturaInfoSec/CVE-2023-26563-26564-26565",
		"https://github.com/Ryan0lb/EC-cloud-e-commerce-system-CVE-application",
		"https://github.com/s1kr10s/EasyChatServer-DOS",
		"https://github.com/saitamang/POC-DUMP",
		"https://github.com/sartlabs/0days",
		"https://github.com/SaumyajeetDas/POC-of-CVE-2022-36271",
		"https://github.com/SaumyajeetDas/Vulnerability",
		"https://github.com/sdpyly/bug_report_canteen",
		"https://github.com/seb1055/cve-2020-27358-27359",
		"https://github.com/secf0ra11/secf0ra11.github.io",
		"https://github.com/Security-AVS/-CVE-2021-26904",
		"https://github.com/securylight/CVES_write_ups",
		"https://github.com/seizer-zyx/Vulnerability",
		"https://github.com/seqred-s-a/gxdlmsdirector-cve",
		"https://github.com/Serces-X/vul_report",
		"https://github.com/shellshok3/Cross-Site-Scripting-XSS",
		"https://github.com/sickcodes/security",
		"https://github.com/silence-silence/xxl-job-lateral-privilege-escalation-vulnerability-",
		"https://github.com/sinemsahn/POC",
		"https://github.com/sleepyvv/vul_report",
		"https://github.com/Snakinya/Vuln",
		"https://github.com/snyk/zip-slip-vulnerability",
		"https://github.com/soheilsamanabadi/vulnerability",
		"https://github.com/soheilsamanabadi/vulnerabilitys",
		"https://github.com/soundarkutty/stored-xss",
		"https://github.com/souravkr529/CSRF-in-Cold-Storage-Management-System",
		"https://github.com/spwpun/ntp-4.2.8p15-cves",
		"https://github.com/sromanhu/Cmsmadesimple-CMS-Stored-XSS",
		"https://github.com/sromanhu/CSZ-CMS-Stored-XSS---Pages-Content",
		"https://github.com/sromanhu/CVE-2023-43339-CMSmadesimple-Reflected-XSS---Installation",
		"https://github.com/sromanhu/CVE-2023-43878-RiteCMS-Stored-XSS---MainMenu",
		"https://github.com/sromanhu/e107-CMS-Stored-XSS---Manage",
		"https://github.com/sromanhu/RiteCMS-Stored-XSS---Home",
		"https://github.com/starnightcyber/miscellaneous",
		"https://github.com/strangebeecorp/security",
		"https://github.com/sunset-move/EasyImages2.0-arbitrary-file-download-vulnerability",
		"https://github.com/SunshineOtaku/Report-CVE",
		"https://github.com/superkojiman/vulnerabilities",
		"https://github.com/syz913/cve-reports",
		"https://github.com/TCSWT/Baby-Care-System",
		"https://github.com/the-emmons/CVE-Disclosures",
		"https://github.com/thehackingverse/Stored-xss-",
		"https://github.com/theyiyibest/Reflected-XSS-on-SockJS",
		"https://github.com/tht1997/CVE_2023",
		"https://github.com/TishaManandhar/Superstore-sql-poc",
		"https://github.com/toyydsBT123/One_of_my_take_on_SourceCodester",
		"https://github.com/Tr0e/CVE_Hunter",
		"https://github.com/transcendent-group/advisories",
		"https://github.com/tremwil/ds3-nrssr-rce",
		"https://github.com/trinity-syt-security/xss_vuln_issue",
		"https://github.com/Trinity-SYT-SECURITY/XSS_vuln_issue",
		"https://github.com/uBlockOrigin/uBlock-issues",
		"https://github.com/umarfarook882/avast_multiple_vulnerability_disclosure",
		"https://github.com/upasvi/CVE-",
		"https://github.com/v2ish1yan/mycve",
		"https://github.com/verf1sh/Poc",
		"https://github.com/versprite/research",
		"https://github.com/vickysuper/Cve_report",
		"https://github.com/VivekPanday12/CVE-",
		"https://github.com/vQAQv/Request-CVE-ID-PoC",
		"https://github.com/vulnerabilities-cve/vulnerabilities",
		"https://github.com/vuls/vuls",
		"https://github.com/wagnerdracha/ProofOfConcept",
		"https://github.com/wandera/public-disclosures",
		"https://github.com/Wh04m1001/ZoneAlarmEoP",
		"https://github.com/whiex/c2Rhc2Rhc2Q-",
		"https://github.com/whitehatl/Vulnerability",
		"https://github.com/wind-cyber/LJCMS-UserTraversal-Vulnerability",
		"https://github.com/wkeyi0x1/vul-report",
		"https://github.com/wsummerhill/BSA-Radar_CVE-Vulnerabilities",
		"https://github.com/wucwu1/CVEApplication",
		"https://github.com/xcodeOn1/xcode0x-CVEs",
		"https://github.com/xf1les/cve-advisories",
		"https://github.com/xiahao90/CVEproject",
		"https://github.com/XIAONIGM/CVEReport",
		"https://github.com/xidaner/CVE_HUNTER",
		"https://github.com/xnobody12/jaws-cms-rce",
		"https://github.com/Xor-Gerke/webray.com.cn",
		"https://github.com/xunyang1/my-vulnerability",
		"https://github.com/xxhzz1/74cmsSE-Arbitrary-file-upload-vulnerability",
		"https://github.com/y1s3m0/vulnfind",
		"https://github.com/yasinyildiz26/Badminton-Center-Management-System",
		"https://github.com/YavuzSahbaz/Limbas-4.3.36.1319-is-vulnerable-to-Cross-Site-Scripting-XSS-",
		"https://github.com/YavuzSahbaz/Red-Planet-Laundry-Management-System-1.0-is-vulnerable-to-SQL",
		"https://github.com/ycdxsb/Vuln",
		"https://github.com/ykosan1/Simple-Task-Scheduling-System-id-SQL-Injection-Unauthenticated",
		"https://github.com/YLoiK/74cmsSE-Arbitrary-file-upload-vulnerability",
		"https://github.com/YorkLee53645349/Cve_report",
		"https://github.com/Yp1oneer/cve_hub",
		"https://github.com/YZLCQX/Mailbox-remote-command-execution",
		"https://github.com/z00z00z00/Safenet_SAC_CVE-2021-42056",
		"https://github.com/zer0yu/CVE_Request",
		"https://github.com/zerrr0/Zerrr0_Vulnerability",
		"https://github.com/Zeyad-Azima/Issabel-stored-XSS",
		"https://github.com/zhao1231/cve_payload",
		"https://github.com/ZhuoNiBa/Delta-DIAEnergie-XSS",
		"https://github.com/Zoe0427/YJCMS",
		"https://github.com/zzh-newlearner/record",
		"https://gitlab.com/FallFur/exploiting-unprotected-admin-funcionalities-on-besder-ip-cameras",
		"https://gitlab.com/gitlab-org/gitlab-ce",      // redirects to gitlab-foss
		"https://gitlab.com/gitlab-org/gitlab-ee",      // redirects to gitlab
		"https://gitlab.com/gitlab-org/gitlab-foss",    // not the canonical source
		"https://gitlab.com/gitlab-org/omnibus-gitlab", // not the source
		"https://gitlab.com/gitlab-org/release",        // not the source
		"https://gitlab.com/kop316/vvm-disclosure",
		"https://gitlab.com/-/snippets/1937042",
		"https://gitlab.com/yongchuank/avast-aswsnx-ioctl-82ac0060-oob-write",
	}
	InvalidRepoRegex = `(?i)/(?:(?:CVEs?)|(?:CVE-\d{4}-\d{4,})(?:/?.*)?|bug_report(?:/.*)?|GitHubAssessments/.*)$`
)

func repoGitWeb(parsedURL *url.URL) (string, error) {
		params := strings.Split(parsedURL.RawQuery, ";")
		for _, param := range params {
			if !strings.HasPrefix(param, "p=") {
				continue
			}
			repo, err := url.JoinPath(strings.TrimSuffix(strings.TrimSuffix(parsedURL.Path, "/gitweb.cgi"), "cgi-bin"), strings.Split(param, "=")[1])
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("git://%s%s", parsedURL.Hostname(), repo), nil
		}
		return "", fmt.Errorf("unsupported GitWeb URL: %s", parsedURL.String())
}

// Returns the base repository URL for supported repository hosts.
func Repo(u string) (string, error) {
	var supportedHosts = []string{
		"bitbucket.org",
		"github.com",
		"gitlab.com",
		"gitlab.org",
		"opendev.org",
		"pagure.io",
		"sourceware.org",
		"xenbits.xen.org",
	}
	var supportedHostPrefixes = []string{
		"git",
		"gitlab",
	}
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	// Disregard the repos we know we don't like (by regex).
	matched, _ := regexp.MatchString(InvalidRepoRegex, u)
	if matched {
		return "", fmt.Errorf("%q matched invalid repo regexp", u)
	}

	for _, dr := range InvalidRepos {
		if strings.HasPrefix(u, dr) {
			return "", fmt.Errorf("%q found in denylist", u)
		}
	}

	// Were we handed a base repository URL from the get go?
	if slices.Contains(supportedHosts, parsedURL.Hostname()) || slices.Contains(supportedHostPrefixes, strings.Split(parsedURL.Hostname(), ".")[0]) {
		pathParts := strings.Split(strings.TrimSuffix(parsedURL.Path, "/"), "/")
		if len(pathParts) == 3 && parsedURL.Path != "/cgi-bin/gitweb.cgi" && parsedURL.Hostname() != "sourceware.org" {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					strings.TrimSuffix(parsedURL.Path, "/")),
				nil
		}
		// GitLab can have a deeper structure to a repo (projects can be within nested groups)
		if len(pathParts) >= 3 && strings.HasPrefix(parsedURL.Hostname(), "gitlab.") &&
			!(strings.Contains(parsedURL.Path, "commit") ||
				strings.Contains(parsedURL.Path, "compare") ||
				strings.Contains(parsedURL.Path, "blob") ||
				strings.Contains(parsedURL.Path, "releases/tag") ||
				strings.Contains(parsedURL.Path, "releases") ||
				strings.Contains(parsedURL.Path, "tags") ||
				strings.Contains(parsedURL.Path, "security/advisories") ||
				strings.Contains(parsedURL.Path, "issues")) {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					strings.TrimSuffix(parsedURL.Path, "/")),
				nil
		}
		if len(pathParts) == 2 && parsedURL.Hostname() == "git.netfilter.org" {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					strings.TrimSuffix(parsedURL.Path, "/")),
				nil
		}
		if len(pathParts) >= 2 && parsedURL.Hostname() == "git.ffmpeg.org" {
			return fmt.Sprintf("%s://%s/%s", parsedURL.Scheme, parsedURL.Hostname(), pathParts[2]), nil
		}
		if parsedURL.Hostname() == "sourceware.org" {
			// Call out to common function for GitWeb URLs
			return repoGitWeb(parsedURL)
		}
		if strings.HasSuffix(parsedURL.Path, ".git") {
			return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
					parsedURL.Hostname(),
					parsedURL.Path),
				nil
		}
	}

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	//
	// They also sometimes have characteristics to map from a web-friendly URL to a clone-friendly repo, on a host-by-host basis.
	//
	//	https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git [web browseable]
	//	https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git [cloneable]
	//
	//	https://git.savannah.gnu.org/cgit/emacs.git [web browseable]
	//	https://git.savannah.gnu.org/git/emacs.git [cloneable]
	//
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		repo := strings.TrimSuffix(parsedURL.Path, "/commit/")

		switch parsedURL.Hostname() {
		case "git.kernel.org":
			repo = strings.Replace(repo, "/cgit", "/pub/scm", 1)

		case "git.savannah.gnu.org":
		case "git.savannah.nongnu.org":
			repo = strings.Replace(repo, "/cgit", "/git", 1)
		}

		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
			parsedURL.Hostname(), repo), nil
	}

	// GitWeb CGI URLs are structured very differently, and require significant translation to get a cloneable URL, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070 -> git://git.gnupg.org/libksba.git
	// https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=11d171f1910b508a81d21faa087ad1af573407d8 -> git://sourceware.org/git/binutils-gdb.git
	if strings.HasSuffix(parsedURL.Path, "/gitweb.cgi") &&
		strings.HasPrefix(parsedURL.RawQuery, "p=") {
		return repoGitWeb(parsedURL)
	}

	// cgit.freedesktop.org is a special snowflake with enough repos to warrant special handling
	// it is a mirror of gitlab.freedesktop.org
	// https://cgit.freedesktop.org/xorg/lib/libXRes/commit/?id=c05c6d918b0e2011d4bfa370c321482e34630b17
	// https://cgit.freedesktop.org/xorg/lib/libXRes
	// http://cgit.freedesktop.org/spice/spice/refs/tags
	if parsedURL.Hostname() == "cgit.freedesktop.org" {
		if strings.HasSuffix(parsedURL.Path, "commit/") &&
			strings.HasPrefix(parsedURL.RawQuery, "id=") {
			repo := strings.TrimSuffix(parsedURL.Path, "/commit/")
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				repo), nil
		}
		if strings.HasSuffix(parsedURL.Path, "refs/tags") {
			repo := strings.TrimSuffix(parsedURL.Path, "/refs/tags")
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				repo), nil
		}
		if len(strings.Split(parsedURL.Path, "/")) == 4 {
			return fmt.Sprintf("https://gitlab.freedesktop.org%s",
				parsedURL.Path), nil
		}
	}

	// GitLab URLs with hyphens in them may have an arbitrary path to the final repo, e.g.
	// https://gitlab.com/mayan-edms/mayan-edms/-/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e
	// https://gitlab.freedesktop.org/xorg/lib/libxpm/-/commit/a3a7c6dcc3b629d7650148
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4
	// https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-2501.json
	if strings.HasPrefix(parsedURL.Hostname(), "gitlab.") && strings.Contains(parsedURL.Path, "/-/") &&
		(strings.Contains(parsedURL.Path, "commit") ||
			strings.Contains(parsedURL.Path, "blob") ||
			strings.Contains(parsedURL.Path, "releases/tag") ||
			strings.Contains(parsedURL.Path, "releases") ||
			strings.Contains(parsedURL.Path, "tags") ||
			strings.Contains(parsedURL.Path, "security/advisories") ||
			strings.Contains(parsedURL.Path, "issues")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.TrimSuffix(strings.Split(parsedURL.Path, "/-/")[0], "/")),
			nil
	}

	// GitHub and GitLab URLs not matching the previous e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://github.com/tensorflow/tensorflow/blob/master/tensorflow/core/ops/math_ops.cc
	// https://gitlab.com/mayan-edms/mayan-edms/commit/9ebe80595afe4fdd1e2c74358d6a9421f4ce130e (this assumes "two-directory" deep repos)
	//
	// This also supports GitHub tag URLs, e.g.
	// https://github.com/JonMagon/KDiskMark/releases/tag/3.1.0
	//
	// This also supports GitHub and Gitlab issue URLs, e.g.:
	// https://github.com/axiomatic-systems/Bento4/issues/755
	// https://gitlab.com/wireshark/wireshark/-/issues/18307
	//
	// This also supports GitHub Security Advisory URLs, e.g.
	// https://github.com/ballcat-projects/ballcat-codegen/security/advisories/GHSA-fv3m-xhqw-9m79

	if (parsedURL.Hostname() == "github.com" || strings.HasPrefix(parsedURL.Hostname(), "gitlab.")) &&
		(strings.Contains(parsedURL.Path, "commit") ||
			strings.Contains(parsedURL.Path, "blob") ||
			strings.Contains(parsedURL.Path, "releases/tag") ||
			strings.Contains(parsedURL.Path, "releases") ||
			strings.Contains(parsedURL.Path, "tags") ||
			strings.Contains(parsedURL.Path, "security/advisories") ||
			strings.Contains(parsedURL.Path, "issues")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// GitHub pull request and comparison URLs are structured differently, e.g.
	// https://github.com/kovidgoyal/kitty/compare/v0.26.1...v0.26.2
	// https://gitlab.com/mayan-edms/mayan-edms/-/compare/development...master
	// https://git.drupalcode.org/project/views/-/compare/7.x-3.21...7.x-3.x
	if strings.Contains(parsedURL.Path, "compare") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// GitHub pull request URLs are structured differently, e.g.
	// https://github.com/google/osv.dev/pull/738
	if parsedURL.Hostname() == "github.com" &&
		strings.Contains(parsedURL.Path, "pull") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// Gitlab merge request URLs are structured differently, e.g.
	// https://gitlab.com/libtiff/libtiff/-/merge_requests/378
	if strings.HasPrefix(parsedURL.Hostname(), "gitlab.") &&
		strings.Contains(parsedURL.Path, "merge_requests") {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// Bitbucket.org URLs are another snowflake, e.g.
	// https://bitbucket.org/ianb/pastescript/changeset/a19e462769b4
	// https://bitbucket.org/jespern/django-piston/commits/91bdaec89543/
	// https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1
	// https://bitbucket.org/snakeyaml/snakeyaml/pull-requests/35
	// https://bitbucket.org/snakeyaml/snakeyaml/issues/566
	// https://bitbucket.org/snakeyaml/snakeyaml/downloads/?tab=tags
	if parsedURL.Hostname() == "bitbucket.org" &&
		(strings.Contains(parsedURL.Path, "changeset") ||
			strings.Contains(parsedURL.Path, "downloads") ||
			strings.Contains(parsedURL.Path, "wiki") ||
			strings.Contains(parsedURL.Path, "issues") ||
			strings.Contains(parsedURL.Path, "security") ||
			strings.Contains(parsedURL.Path, "pull-requests") ||
			strings.Contains(parsedURL.Path, "commits")) {
		return fmt.Sprintf("%s://%s%s", parsedURL.Scheme,
				parsedURL.Hostname(),
				strings.Join(strings.Split(parsedURL.Path, "/")[0:3], "/")),
			nil
	}

	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Repo(): unsupported URL: %s", u)
}

// Returns the commit ID from supported links.
func Commit(u string) (string, error) {
	parsedURL, err := url.Parse(u)
	if err != nil {
		return "", err
	}

	// cGit URLs are structured another way, e.g.
	// https://git.dpkg.org/cgit/dpkg/dpkg.git/commit/?id=faa4c92debe45412bfcf8a44f26e827800bb24be
	// https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=817b8b9c5396d2b2d92311b46719aad5d3339dbe
	if strings.HasPrefix(parsedURL.Path, "/cgit") &&
		strings.HasSuffix(parsedURL.Path, "commit/") &&
		strings.HasPrefix(parsedURL.RawQuery, "id=") {
		return strings.Split(parsedURL.RawQuery, "=")[1], nil
	}

	// GitWeb cgi-bin URLs are structured another way, e.g.
	// https://git.gnupg.org/cgi-bin/gitweb.cgi?p=libksba.git;a=commit;h=f61a5ea4e0f6a80fd4b28ef0174bee77793cf070
	if strings.HasPrefix(parsedURL.Path, "/cgi-bin/gitweb.cgi") &&
		strings.Contains(parsedURL.RawQuery, "a=commit") {
		params := strings.Split(parsedURL.RawQuery, ";")
		for _, param := range params {
			if !strings.HasPrefix(param, "h=") {
				continue
			}
			return strings.Split(param, "=")[1], nil
		}
	}

	// FFMpeg's GitWeb seems to be it's own unique snowflake, e.g.
	// https://git.ffmpeg.org/gitweb/ffmpeg.git/commit/c94875471e3ba3dc396c6919ff3ec9b14539cd71
	if strings.HasPrefix(parsedURL.Path, "/gitweb/") && len(strings.Split(parsedURL.Path, "/")) == 5 {
		return strings.Split(parsedURL.Path, "/")[4], nil
	}

	// GitHub and GitLab commit URLs are structured one way, e.g.
	// https://github.com/MariaDB/server/commit/b1351c15946349f9daa7e5297fb2ac6f3139e4a8
	// https://gitlab.freedesktop.org/virgl/virglrenderer/-/commit/b05bb61f454eeb8a85164c8a31510aeb9d79129c
	// https://gitlab.com/qemu-project/qemu/-/commit/4367a20cc4

	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	directory, possibleCommitHash := path.Split(parsedURL.Path)
	if strings.HasSuffix(directory, "commit/") {
		return strings.TrimSuffix(possibleCommitHash, ".patch"), nil
	}

	// and Bitbucket.org commit URLs are similiar yet slightly different:
	// https://bitbucket.org/openpyxl/openpyxl/commits/3b4905f428e1
	//
	// Some bitbucket.org commit URLs have been observed in the wild with a trailing /, which will
	// change the behaviour of path.Split(), so normalize the path to be tolerant of this.
	if parsedURL.Host == "bitbucket.org" {
		parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
		directory, possibleCommitHash := path.Split(parsedURL.Path)
		if strings.HasSuffix(directory, "commits/") {
			return possibleCommitHash, nil
		}
	}

	// TODO(apollock): add support for resolving a GitHub PR to a commit hash

	// If we get to here, we've encountered an unsupported URL.
	return "", fmt.Errorf("Commit(): unsupported URL: %s", u)
}

// Detect linkrot and handle link decay in HTTP(S) links via HEAD request with exponential backoff.
func ValidateAndCanonicalizeLink(link string) (canonicalLink string, err error) {
	u, err := url.Parse(link)
	if !slices.Contains([]string{"http", "https"}, u.Scheme) {
		// Handle what's presumably a git:// URL.
		return link, err
	}
	backoff := retry.NewExponential(1 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		resp, err := http.Head(link)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		switch resp.StatusCode / 100 {
		// 4xx response codes are an instant fail.
		case 4:
			return fmt.Errorf("bad response: %v", resp.StatusCode)
		// 5xx response codes are retriable.
		case 5:
			return retry.RetryableError(fmt.Errorf("bad response: %v", resp.StatusCode))
		// Anything else is acceptable.
		default:
			canonicalLink = resp.Request.URL.String()
			return nil
		}
	}); err != nil {
		return link, fmt.Errorf("unable to determine validity of %q: %v", link, err)
	}
	return canonicalLink, nil
}

// For URLs referencing commits in supported Git repository hosts, return a cloneable AffectedCommit.
func extractGitCommit(link string, commitType CommitType) (ac AffectedCommit, err error) {
	r, err := Repo(link)
	if err != nil {
		return ac, err
	}

	c, err := Commit(link)
	if err != nil {
		return ac, err
	}

	// If URL doesn't validate, treat it as linkrot.
	// Possible TODO(apollock): restart the entire extraction process when the
	// repo changes (i.e. handle a redirect to a completely different host,
	// instead of a redirect within GitHub)
	r, err = ValidateAndCanonicalizeLink(r)
	if err != nil {
		return ac, err
	}

	ac.SetRepo(r)

	switch commitType {
	case Introduced:
		ac.SetIntroduced(c)
	case LastAffected:
		ac.SetLastAffected(c)
	case Limit:
		ac.SetLimit(c)
	case Fixed:
		ac.SetFixed(c)
	}

	return ac, nil
}

func hasVersion(validVersions []string, version string) bool {
	if len(validVersions) == 0 {
		return true
	}
	return versionIndex(validVersions, version) != -1
}

func versionIndex(validVersions []string, version string) int {
	for i, cur := range validVersions {
		if cur == version {
			return i
		}
	}
	return -1
}

func nextVersion(validVersions []string, version string) (string, error) {
	idx := versionIndex(validVersions, version)
	if idx == -1 {
		return "", fmt.Errorf("warning: %s is not a valid version", version)
	}

	idx += 1
	if idx >= len(validVersions) {
		return "", fmt.Errorf("warning: %s does not have a version that comes after", version)
	}

	return validVersions[idx], nil
}

func processExtractedVersion(version string) string {
	version = strings.Trim(version, ".")
	// Version should contain at least a "." or a number.
	if !strings.ContainsAny(version, ".") && !strings.ContainsAny(version, "0123456789") {
		return ""
	}

	return version
}

func extractVersionsFromDescription(validVersions []string, description string) ([]AffectedVersion, []string) {
	// Match:
	//  - x.x.x before x.x.x
	//  - x.x.x through x.x.x
	//  - through x.x.x
	//  - before x.x.x
	pattern := regexp.MustCompile(`(?i)([\w.+\-]+)?\s+(through|before)\s+(?:version\s+)?([\w.+\-]+)`)
	matches := pattern.FindAllStringSubmatch(description, -1)
	if matches == nil {
		return nil, []string{"Failed to parse versions from description"}
	}

	var notes []string
	var versions []AffectedVersion
	for _, match := range matches {
		// Trim periods that are part of sentences.
		introduced := processExtractedVersion(match[1])
		fixed := processExtractedVersion(match[3])
		lastaffected := ""
		if match[2] == "through" {
			// "Through" implies inclusive range, so the fixed version is the one that comes after.
			var err error
			fixed, err = nextVersion(validVersions, fixed)
			if err != nil {
				notes = append(notes, err.Error())
				// if that inference failed, we know this version was definitely still vulnerable.
				lastaffected = cleanVersion(match[3])
				notes = append(notes, fmt.Sprintf("Using %s as last_affected version instead", cleanVersion(match[3])))
			}
		}

		if introduced == "" && fixed == "" && lastaffected == "" {
			notes = append(notes, "Failed to match version range from description")
			continue
		}

		if introduced != "" && !hasVersion(validVersions, introduced) {
			notes = append(notes, fmt.Sprintf("Extracted introduced version %s is not a valid version", introduced))
		}
		if fixed != "" && !hasVersion(validVersions, fixed) {
			notes = append(notes, fmt.Sprintf("Extracted fixed version %s is not a valid version", fixed))
		}
		if lastaffected != "" && !hasVersion(validVersions, lastaffected) {
			notes = append(notes, fmt.Sprintf("Extracted last_affected version %s is not a valid version", lastaffected))
		}
		// Favour fixed over last_affected for schema compliance.
		if fixed != "" && lastaffected != "" {
			lastaffected = ""
		}

		versions = append(versions, AffectedVersion{
			Introduced:   introduced,
			Fixed:        fixed,
			LastAffected: lastaffected,
		})
	}

	return versions, notes
}

func cleanVersion(version string) string {
	// Versions can end in ":" for some reason.
	return strings.TrimRight(version, ":")
}

func ExtractVersionInfo(cve CVE, validVersions []string) (v VersionInfo, notes []string) {
	for _, reference := range cve.References {
		// (Potentially faulty) Assumption: All viable Git commit reference links are fix commits.
		if commit, err := extractGitCommit(reference.Url, Fixed); err == nil {
			v.AffectedCommits = append(v.AffectedCommits, commit)
		}
	}

	gotVersions := false
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			if node.Operator != "OR" {
				continue
			}

			for _, match := range node.CPEMatch {
				if !match.Vulnerable {
					continue
				}

				introduced := ""
				fixed := ""
				lastaffected := ""
				if match.VersionStartIncluding != nil {
					introduced = cleanVersion(*match.VersionStartIncluding)
				} else if match.VersionStartExcluding != nil {
					var err error
					introduced, err = nextVersion(validVersions, cleanVersion(*match.VersionStartExcluding))
					if err != nil {
						notes = append(notes, err.Error())
					}
				}

				if match.VersionEndExcluding != nil {
					fixed = cleanVersion(*match.VersionEndExcluding)
				} else if match.VersionEndIncluding != nil {
					var err error
					// Infer the fixed version from the next version after.
					fixed, err = nextVersion(validVersions, cleanVersion(*match.VersionEndIncluding))
					if err != nil {
						notes = append(notes, err.Error())
						// if that inference failed, we know this version was definitely still vulnerable.
						lastaffected = cleanVersion(*match.VersionEndIncluding)
						notes = append(notes, fmt.Sprintf("Using %s as last_affected version instead", cleanVersion(*match.VersionEndIncluding)))
					}
				}

				if introduced == "" && fixed == "" && lastaffected == "" {
					// See if a last affected version is inferable from the CPE string.
					// In this situation there is no known introduced version.
					CPE, err := ParseCPE(match.Criteria)
					if err != nil {
						continue
					}
					if CPE.Part != "a" {
						// Skip operating system CPEs.
						continue
					}
					if slices.Contains([]string{"NA", "ANY"}, CPE.Version) {
						// These are meaningless converting to commits.
						continue
					}
					lastaffected = CPE.Version
					if CPE.Update != "ANY" {
						lastaffected += "-" + CPE.Update
					}
				}

				if introduced == "" && fixed == "" && lastaffected == "" {
					continue
				}

				if introduced != "" && !hasVersion(validVersions, introduced) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid introduced version", introduced))
				}

				if fixed != "" && !hasVersion(validVersions, fixed) {
					notes = append(notes, fmt.Sprintf("Warning: %s is not a valid fixed version", fixed))
				}

				gotVersions = true
				possibleNewAffectedVersion := AffectedVersion{
					Introduced:   introduced,
					Fixed:        fixed,
					LastAffected: lastaffected,
				}
				if slices.Contains(v.AffectedVersions, possibleNewAffectedVersion) {
					// Avoid appending duplicates
					continue
				}
				v.AffectedVersions = append(v.AffectedVersions, possibleNewAffectedVersion)
			}
		}
	}
	if !gotVersions {
		var extractNotes []string
		v.AffectedVersions, extractNotes = extractVersionsFromDescription(validVersions, EnglishDescription(cve))
		notes = append(notes, extractNotes...)
		if len(v.AffectedVersions) > 0 {
			log.Printf("[%s] Extracted versions from description = %+v", cve.ID, v.AffectedVersions)
		}
	}

	if len(v.AffectedVersions) == 0 {
		notes = append(notes, "No versions detected.")
	}

	if len(notes) != 0 && len(validVersions) > 0 {
		notes = append(notes, "Valid versions:")
		for _, version := range validVersions {
			notes = append(notes, "  - "+version)
		}
	}

	// Remove any lastaffected versions in favour of fixed versions.
	if v.HasFixedVersions() {
		affectedVersionsWithoutLastAffected := []AffectedVersion{}
		for _, av := range v.AffectedVersions {
			if av.LastAffected != "" {
				continue
			}
			affectedVersionsWithoutLastAffected = append(affectedVersionsWithoutLastAffected, av)
		}
		v.AffectedVersions = affectedVersionsWithoutLastAffected
	}
	return v, notes
}

func CPEs(cve CVE) []string {
	var cpes []string
	for _, config := range cve.Configurations {
		for _, node := range config.Nodes {
			for _, match := range node.CPEMatch {
				cpes = append(cpes, match.Criteria)
			}
		}
	}

	return cpes
}

// There are some weird and wonderful rules about quoting with strings in CPEs
// See 5.3.2 of NISTIR 7695 for more details
// https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
func RemoveQuoting(s string) (result string) {
	return strings.Replace(s, "\\", "", -1)
}

// Parse a well-formed CPE string into a struct.
func ParseCPE(formattedString string) (*CPE, error) {
	if !strings.HasPrefix(formattedString, "cpe:") {
		return nil, fmt.Errorf("%q does not have expected 'cpe:' prefix", formattedString)
	}

	wfn, err := naming.UnbindFS(formattedString)

	if err != nil {
		return nil, err
	}

	return &CPE{
		CPEVersion: strings.Split(formattedString, ":")[1],
		Part:       wfn.GetString("part"),
		Vendor:     RemoveQuoting(wfn.GetString("vendor")),
		Product:    RemoveQuoting(wfn.GetString("product")),
		Version:    RemoveQuoting(wfn.GetString("version")),
		Update:     wfn.GetString("update"),
		Edition:    wfn.GetString("edition"),
		Language:   wfn.GetString("language"),
		SWEdition:  wfn.GetString("sw_edition"),
		TargetSW:   wfn.GetString("target_sw"),
		TargetHW:   wfn.GetString("target_hw"),
		Other:      wfn.GetString("other")}, nil
}

// Normalize version strings found in CVE CPE Match data or Git tags.
// Use the same logic and behaviour as normalize_tag() osv/bug.py for consistency.
func NormalizeVersion(version string) (normalizedVersion string, e error) {
	// Keep in sync with the intent of https://github.com/google/osv.dev/blob/26050deb42785bc5a4dc7d802eac8e7f95135509/osv/bug.py#L31
	var validVersion = regexp.MustCompile(`(?i)(\d+|(?:rc|alpha|beta|preview)\d*)`)
	var validVersionText = regexp.MustCompile(`(?i)(?:rc|alpha|beta|preview)\d*`)
	components := validVersion.FindAllString(version, -1)
	if components == nil {
		return "", fmt.Errorf("%q is not a supported version", version)
	}
	// If the very first component happens to accidentally match the strings we support, remove it.
	// This is necessary because of the lack of negative lookbehind assertion support in RE2.
	if validVersionText.MatchString(components[0]) {
		components = slices.Delete(components, 0, 1)
	}
	normalizedVersion = strings.Join(components, "-")
	return normalizedVersion, e
}
