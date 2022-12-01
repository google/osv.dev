/*
cperepos analyzes the NVD CPE Dictionary for Open Source repository information.
It reads the NVD CPE Dictionary XML file and outputs a JSON map of CPE products to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

	go run cmd/cperepos/main.go [flags]

The flags are:

	  --cpe_dictionary
		The path to the uncompressed NVD CPE Dictionary XML file, see https://nvd.nist.gov/products/cpe

	  --debian_metadata_path
	        The path to a directory containing a local mirror of Debian copyright metadata, see README.md

	  --output_dir
	        The directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in

	  --gcp_logging_project
		The GCP project ID to utilise for Cloud Logging. Set to the empty string to log to stdout

	  --verbose
		Output additional telemetry to stdout
*/
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"golang.org/x/exp/slices"
)

type CPEDict struct {
	XMLName  xml.Name  `xml:"cpe-list"`
	CPEItems []CPEItem `xml:"cpe-item"`
}

type CPEItem struct {
	XMLName    xml.Name    `xml:"cpe-item" json:"-"`
	Name       string      `xml:"name,attr" json:"name"`
	Title      string      `xml:"title" json:"title"`
	References []Reference `xml:"references>reference" json:"references"`
	CPE23      CPE23Item   `xml:"cpe23-item" json:"cpe23-item"`
}

type Reference struct {
	URL         string `xml:"href,attr" json:"URL"`
	Description string `xml:",chardata" json:"description"`
}

type CPE23Item struct {
	Name string `xml:"name,attr"`
}

type VendorProductToRepoMap map[string]map[string][]string

const (
	CPEDictionaryDefault = "cve_jsons/nvdcpematch-1.0.json"
	OutputDirDefault     = "."
	projectId            = "oss-vdb"
)

var (
	Logger utility.LoggerWrapper
	// These repos should never be considered authoritative for a product.
	// TODO(apollock): read this from an external file
	InvalidRepos = []string{
		"https://github.com/abhiunix/goo-blog-App-CVE",
		"https://github.com/agadient/SERVEEZ-CVE",
		"https://github.com/alwentiu/COVIDSafe-CVE-2020-12856",
		"https://github.com/ciph0x01/Simple-Exam-Reviewer-Management-System-CVE",
		"https://github.com/CVEProject/cvelist", // Heavily in Advisory URLs, sometimes shows up elsewhere
		"https://github.com/DayiliWaseem/CVE-2022-39196-",
		"https://github.com/eddietcc/CVEnotes",
		"https://github.com/Fadavvi/CVE-2018-17431-PoC",
		"https://github.com/GitHubAssessments/CVE_Assessments_11_2019",
		"https://github.com/github/cvelist", // Fork of https://github.com/CVEProject/cvelist
		"https://github.com/Gr4y21/My-CVE-IDs",
		"https://github.com/hemantsolo/CVE-Reference",
		"https://github.com/huclilu/CVE_Add",
		"https://github.com/i3umi3iei3ii/CentOS-Control-Web-Panel-CVE",
		"https://github.com/Kenun99/CVE-batdappboomx",
		"https://github.com/lukaszstu/SmartAsset-CORS-CVE-2020-26527",
		"https://github.com/MacherCS/CVE_Evoh_Contract",
		"https://github.com/martinkubecka/CVE-References",
		"https://github.com/MrR3boot/CVE-Hunting",
		"https://github.com/nu11secur1ty/CVE-nu11secur1ty",
		"https://github.com/Orange-Cyberdefense/CVE-repository",
		"https://github.com/post-cyberlabs/CVE-Advisory",
		"https://github.com/refi64/CVE-2020-25265-25266",
		"https://github.com/riteshgohil/My_CVE_References",
		"https://github.com/roughb8722/CVE-2021-3122-Details",
		"https://github.com/Ryan0lb/EC-cloud-e-commerce-system-CVE-application",
		"https://github.com/SaumyajeetDas/POC-of-CVE-2022-36271",
		"https://github.com/Security-AVS/-CVE-2021-26904",
		"https://github.com/vQAQv/Request-CVE-ID-PoC",
		"https://github.com/wsummerhill/BSA-Radar_CVE-Vulnerabilities",
		"https://github.com/xiahao90/CVEproject",
		"https://github.com/z00z00z00/Safenet_SAC_CVE-2021-42056",
	}
	// Match repos with "CVE", "CVEs" or a pure CVE number in their name, anything from GitHubAssessments
	InvalidRepoRegex   = `/(?:(?:CVEs?)|(?:CVE-\d{4}-\d{4,})|GitHubAssessments/.*|advisories/GHSA.*)$`
	CPEDictionaryFile  = flag.String("cpe_dictionary", CPEDictionaryDefault, "CPE Dictionary file to parse")
	OutputDir          = flag.String("output_dir", OutputDirDefault, "Directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in")
	GCPLoggingProject  = flag.String("gcp_logging_project", projectId, "GCP project ID to use for logging, set to an empty string to log locally only")
	DebianMetadataPath = flag.String("debian_metadata_path", "", "Path to Debian copyright metadata")
	Verbose            = flag.Bool("verbose", false, "Output some telemetry to stdout during execution")
)

func LoadCPEDictionary(f string) (CPEDict, error) {
	xmlFile, err := os.Open(f)
	if err != nil {
		Logger.Fatalf("Failed to open %s: %v", f, err)
	}

	defer xmlFile.Close()

	byteValue, _ := ioutil.ReadAll(xmlFile)

	var c CPEDict
	xml.Unmarshal(byteValue, &c)

	return c, nil
}

// Outputs a JSON file of the product-to-repo map.
func outputProductToRepoMap(prm VendorProductToRepoMap, f io.Writer) error {
	productsWithoutRepos := 0
	for p := range prm {
		if len(prm[p]) == 0 {
			productsWithoutRepos++
			delete(prm, p) // we don't want the repo-less products in our JSON output
			continue
		}
	}

	e := json.NewEncoder(f)

	if err := e.Encode(&prm); err != nil {
		return err
	}

	if *Verbose {
		fmt.Printf("Loaded information about %d products, %d do not have repos\n", len(prm), productsWithoutRepos)
	}
	Logger.Infof("Loaded information about %d application products, %d do not have repos", len(prm), productsWithoutRepos)
	return nil
}

// Outputs a CSV file of the description frequency map, sorted in descending order.
func outputDescriptionFrequency(df map[string]int, f io.Writer) error {
	descriptions := make([]string, 0, len(df))
	for description := range df {
		descriptions = append(descriptions, description)
	}
	sort.SliceStable(descriptions, func(i, j int) bool {
		return df[descriptions[i]] > df[descriptions[j]]
	})

	w := csv.NewWriter(f)

	if err := w.Write([]string{"Description", "Frequency"}); err != nil {
		return err
	}
	for _, d := range descriptions {
		if err := w.Write([]string{d, strconv.Itoa(df[d])}); err != nil {
			return err
		}
	}

	w.Flush()

	if err := w.Error(); err != nil {
		return err
	}

	if *Verbose {
		fmt.Printf("Seen %d descriptions \n", len(df))
	}
	Logger.Infof("Seen %d descriptions", len(df))
	return nil
}

// Checks if a URL relates to the FSF.
func IsGNUURL(url string) bool {
	re := regexp.MustCompile(`^https?://.*\.(?:non)?gnu\.org/`)

	return re.MatchString(url)
}

// Tries to translate Savannah URLs to their corresponding Git repository URL.
func MaybeTranslateSavannahURL(u string) (string, bool) {
	type GNUPlaceholder struct {
		GNUOrNonGNU string
		Path        string
	}
	var tpl bytes.Buffer

	supportedHostnames := []string{
		"download.savannah.gnu.org",
		"savannah.gnu.org",
		"download.savannah.gnu.org",
		"download-mirror.savannah.gnu.org",
		"download.savannah.nongnu.org",
		"savannah.nongnu.org",
		"download.savannah.nongnu.org",
		"download-mirror.savannah.nongnu.org",
	}

	// Get hostname out of URL
	parsedURL, err := url.Parse(u)
	if err != nil {
		panic(err)
	}

	if slices.Contains(supportedHostnames, parsedURL.Hostname()) {
		hostnameParts := strings.Split(parsedURL.Hostname(), ".")
		// Pull out the "nongnu" or "gnu" part of the hostname
		domain := GNUPlaceholder{hostnameParts[len(hostnameParts)-2], path.Base(parsedURL.Path)}
		savannahGitRepoTemplate, err := template.New("SavannahGitRepoURL").Parse("https://git.savannah.{{ .GNUOrNonGNU }}.org/git/{{ .Path }}.git")
		if err != nil {
			panic(err)
		}
		err = savannahGitRepoTemplate.Execute(&tpl, domain)
		return tpl.String(), true
	}

	// Return the original URL unmodified
	return u, false
}

// Returns the data associated with the ^Source: line of a machine-readable Debian copyright file
// See https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
func MaybeGetSourceFromDebianCopyright(copyrightFile string) (string, bool) {
	re := regexp.MustCompile(`^Source: (.*)$`)

	file, err := os.Open(copyrightFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Check the first line to see if we have a machine-readable copyright file
	scanner.Scan()
	if scanner.Text() != "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/" {
		return "", false
	}

	for scanner.Scan() {
		line := scanner.Text()
		match := re.FindStringSubmatch(line)
		if match != nil {
			return match[1], true
		}
	}

	return "", false
}

// Tries to find a Debian copyright file for the package and returns the source URL if IsRepoURL() agrees.
func MaybeGetSourceRepoFromDebian(mdir string, pkg string) string {
	var metadata string
	if strings.HasPrefix(pkg, "lib") {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0:4]), pkg, "unstable_copyright")
	} else {
		metadata = path.Join(mdir, "changelogs/main", string(pkg[0]), pkg, "unstable_copyright")
	}
	if _, err := os.Stat(metadata); err == nil {
		// parse the copyright file and go from here
		Logger.Infof("FYI: Will look at %s", metadata)
		possibleRepo, ok := MaybeGetSourceFromDebianCopyright(metadata)
		if !ok {
			return ""
		}
		if utility.IsRepoURL(possibleRepo) {
			return possibleRepo
		}
		// Incorporate Savannah URL to Git translation here
		if IsGNUURL(possibleRepo) {
			repo, translated := MaybeTranslateSavannahURL(possibleRepo)
			if translated {
				return repo
			}
		}
		Logger.Infof("FYI: Disregarding %s", possibleRepo)
	}
	return ""
}

// Analyze CPE Dictionary
func analyzeCPEDictionary(d CPEDict) (ProductToRepo VendorProductToRepoMap, DescriptionFrequency map[string]int) {
	ProductToRepo = make(VendorProductToRepoMap)
	DescriptionFrequency = make(map[string]int)
	for _, c := range d.CPEItems {
		CPE, err := cves.ParseCPE(c.CPE23.Name)
		if err != nil {
			Logger.Infof("Failed to parse %q", c.CPE23.Name)
			continue
		}
		if CPE.Part != "a" {
			// Not interested in hardware or operating systems.
			continue
		}
		for _, r := range c.References {
			DescriptionFrequency[r.Description] += 1
			repo, err := cves.Repo(r.URL)
			if err != nil {
				Logger.Infof("Disregarding %q for %q/%q (%s) because %v", r.URL, CPE.Vendor, CPE.Product, r.Description, err)
				continue
			}
			// Disregard the repos we know we don't like.
			matched, _ := regexp.MatchString(InvalidRepoRegex, repo)
			if matched {
				Logger.Infof("Disliking %q for %q/%q (%s) (matched regexp)", repo, CPE.Vendor, CPE.Product, r.Description)
				continue
			}
			if slices.Contains(InvalidRepos, repo) {
				Logger.Infof("Disliking %q for %q/%q (%s)", repo, CPE.Vendor, CPE.Product, r.Description)
				continue
			}
			if slices.Contains(ProductToRepo[CPE.Vendor][CPE.Product], repo) {
				continue
			}
			Logger.Infof("Liking %q for %q/%q (%s)", repo, CPE.Vendor, CPE.Product, r.Description)
			ProductToRepo[CPE.Vendor] = map[string][]string{CPE.Product: append(ProductToRepo[CPE.Vendor][CPE.Product], repo)}
		}
		// If we've arrived to this point and not calculated any repos for the product, try Debian
		if len(ProductToRepo[CPE.Vendor][CPE.Product]) == 0 && *DebianMetadataPath != "" {
			Logger.Infof("Trying to derive a repo from Debian for %q/%q", CPE.Vendor, CPE.Product)
			repo := MaybeGetSourceRepoFromDebian(*DebianMetadataPath, CPE.Product)
			if repo != "" {
				Logger.Infof("Derived repo: %s", repo)
				ProductToRepo[CPE.Vendor] = map[string][]string{CPE.Product: []string{repo}}
			}
		}
	}
	return ProductToRepo, DescriptionFrequency
}

func main() {
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), "Utility to analyze NVD CPE Dictionary\n\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if *GCPLoggingProject != "" {
		client, err := logging.NewClient(context.Background(), *GCPLoggingProject)
		if err != nil {
			log.Fatalf("Failed to create client: %v", err)
		}
		defer client.Close()
		Logger.GCloudLogger = client.Logger("cperepos")
	}

	CPEDictionary, err := LoadCPEDictionary(*CPEDictionaryFile)
	if err != nil {
		Logger.Fatalf("Failed to load %s: %v", *CPEDictionaryFile, err)
	}

	productToRepo, descriptionFrequency := analyzeCPEDictionary(CPEDictionary)

	mappingFile, err := os.Create(filepath.Join(*OutputDir, "cpe_product_to_repo.json"))
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer mappingFile.Close()
	err = outputProductToRepoMap(productToRepo, mappingFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	frequencyFile, err := os.Create(filepath.Join(*OutputDir, "cpe_reference_description_frequency.csv"))
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer frequencyFile.Close()
	err = outputDescriptionFrequency(descriptionFrequency, frequencyFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
}
