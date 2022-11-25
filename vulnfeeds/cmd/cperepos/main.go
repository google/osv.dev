/*
cperepos analyzes the NVD CPE Dictionary for Open Source repository information.
It reads the NVD CPE Dictionary XML file and outputs a JSON map of CPE products to discovered repository URLs.

It can also output on stdout additional data about colliding CPE package names.

Usage:

	go run cmd/cperepos/main.go [flags]

The flags are:

	  --cpe_dictionary
		The path to the uncompressed NVD CPE Dictionary XML file, see https://nvd.nist.gov/products/cpe

	  --output_dir
	        The directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in

	  --gcp_logging_project
		The GCP project ID to utilise for Cloud Logging. Set to the empty string to log to stdout

	  --verbose
		Output additional telemetry to stdout
*/
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

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
	InvalidRepoRegex  = `/(?:(?:CVEs?)|(?:CVE-\d{4}-\d{4,})|GitHubAssessments/.*|advisories/GHSA.*)$`
	CPEDictionaryFile = flag.String("cpe_dictionary", CPEDictionaryDefault, "CPE Dictionary file to parse")
	OutputDir         = flag.String("output_dir", OutputDirDefault, "Directory to output cpe_product_to_repo.json and cpe_reference_description_frequency.csv in")
	GCPLoggingProject = flag.String("gcp_logging_project", projectId, "GCP project ID to use for logging, set to an empty string to log locally only")
	Verbose           = flag.Bool("verbose", false, "Output some telemetry to stdout during execution")
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
func outputProductToRepoMap(prm map[string][]string, f io.Writer) error {
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

// Analyze CPE Dictionary
func analyzeCPEDictionary(d CPEDict) (ProductToRepo map[string][]string, DescriptionFrequency map[string]int, ProductToVendor map[string][]string) {
	ProductToRepo = make(map[string][]string)
	DescriptionFrequency = make(map[string]int)
	ProductToVendor = make(map[string][]string)
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
		// Gather the data to answer the question: "are there product name collisions?"
		if *Verbose {
			if _, exists := ProductToVendor[CPE.Product]; exists {
				if !slices.Contains(ProductToVendor[CPE.Product], CPE.Vendor) {
					ProductToVendor[CPE.Product] = append(ProductToVendor[CPE.Product], CPE.Vendor)
				}
			} else {
				ProductToVendor[CPE.Product] = []string{CPE.Vendor}
			}
		}
		for _, r := range c.References {
			DescriptionFrequency[r.Description] += 1
			repo, err := cves.Repo(r.URL)
			if err != nil {
				Logger.Infof("Disregarding %q for %q (%s) because %v", r.URL, CPE.Product, r.Description, err)
				continue
			}
			// Disregard the repos we know we don't like.
			matched, _ := regexp.MatchString(InvalidRepoRegex, repo)
			if matched {
				Logger.Infof("Disliking %q for %q (%s) (matched regexp)", repo, CPE.Product, r.Description)
				continue
			}
			if slices.Contains(InvalidRepos, repo) {
				Logger.Infof("Disliking %q for %q (%s)", repo, CPE.Product, r.Description)
				continue
			}
			if !slices.Contains(ProductToRepo[CPE.Product], repo) {
				Logger.Infof("Liking %q for %q (%s)", repo, CPE.Product, r.Description)
				ProductToRepo[CPE.Product] = append(ProductToRepo[CPE.Product], repo)
			}
		}
	}
	return ProductToRepo, DescriptionFrequency, ProductToVendor
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

	productToRepo, descriptionFrequency, productToVendor := analyzeCPEDictionary(CPEDictionary)

	mappingFile, err := os.Create(filepath.Join(*OutputDir, "cpe_product_to_repo.json"))
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	defer mappingFile.Close()
	err = outputProductToRepoMap(productToRepo, mappingFile)
	if err != nil {
		Logger.Fatalf("%v", err)
	}
	// Answer the question: "are there product name collisions?"
	if *Verbose {
		for product, vendors := range productToVendor {
			if len(vendors) == 1 {
				continue
			}
			Logger.Infof("Product %s has >1 vendors: [%s]", product, strings.Join(vendors, ", "))
			fmt.Printf("Product %s has >1 vendors: [%s]\n", product, strings.Join(vendors, ", "))
		}
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
