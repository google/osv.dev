package main

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"

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
	projectId            = "oss-vdb"
)

var (
	Logger            utility.LoggerWrapper
	ValidDescriptions = []string{
		"Version",
		"Vendor",
		"Change Log",
		"Product",
		// Brings in https://github.com/CVEProject/cvelist, which is not relevant
		// "Advisory",
		"Project",
		"Vendor website", // unlikely to be a repo, but statistically significant as a description
		"product changelog",
		"Version information",
		"vendor website", // unlikely to be a repo, but statistically significant as a description
		"Vendor Website", // unlikely to be a repo, but statistically significant as a description
		"version information",
		"product version information",
		"product information",
		"Product changelog",
		"vendor product information",
		"Changelog",
		"Version Information",
		"Vendor changelog",
		"project information",
		"product release information",
		"product release notes",
		"vendor product website",
		"Product version information",
		"vendor changelog",
	}
	// These repos should never be considered authoritative for a product.
	InvalidRepos = []string{
		"https://github.com/CVEProject/cvelist", // Heavily in Advisory URLs, sometimes shows up elsewhere
		"https://github.com/github/cvelist",     // Fork of the above
	}
	CPEDictionaryFile = flag.String("cpe_dictionary", CPEDictionaryDefault, "CPE Dictionary file to parse")
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

func main() {
	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	Logger.GCloudLogger = client.Logger("cperepos")
	flag.Parse()

	CPEDictionary, err := LoadCPEDictionary(*CPEDictionaryFile)
	if err != nil {
		Logger.Fatalf("Failed to load %s: %v", *CPEDictionaryFile, err)
	}
	ProductToRepo := make(map[string]*string)
	DescriptionFrequency := make(map[string]int)
	for _, c := range CPEDictionary.CPEItems {
		CPE, err := cves.ParseCPE(c.CPE23.Name)
		if err != nil {
			Logger.Infof("Failed to parse %q", c.CPE23.Name)
			continue
		}
		if CPE.Part != "a" {
			// Not interested in hardware or operating systems.
			continue
		}
		if _, exists := ProductToRepo[CPE.Product]; !exists {
			// This way every seen product will exist in the map,
			// and ones we never determine a repo for will have a
			// nil value.
			ProductToRepo[CPE.Product] = nil
		} else {
			Logger.Infof("Already have %q for %q, skipping relookup", *ProductToRepo[CPE.Product], CPE.Product)
			continue
		}
		for _, r := range c.References {
			DescriptionFrequency[r.Description] += 1
			repo, err := cves.Repo(r.URL)
			if err != nil {
				Logger.Infof("Disregarding %q for %q (%s) because %v", r.URL, CPE.Product, r.Description, err)
				continue
			}
			// Disregard the repos we know we don't like.
			if slices.Contains(InvalidRepos, repo) {
				Logger.Infof("Disliking %q for %q (%s)", repo, CPE.Product, r.Description)
				continue
			}
			// Don't consider URL descriptions not explicitly allowlisted to reduce invalidity.
			if !slices.Contains(ValidDescriptions, r.Description) {
				Logger.Infof("Disregarding %q for %q (%s)", r.URL, CPE.Product, r.Description)
				continue
			}
			Logger.Infof("Liking %q for %q (%s)", repo, CPE.Product, r.Description)
			ProductToRepo[CPE.Product] = &repo
		}
	}
	productsWithoutRepos := 0
	products := make([]string, 0, len(ProductToRepo))
	for p := range ProductToRepo {
		products = append(products, p)
	}
	sort.Strings(products)
	for _, product := range products {
		if ProductToRepo[product] == nil {
			productsWithoutRepos++
			continue
		}
		fmt.Printf("%s -> %s\n", product, *ProductToRepo[product])
	}
	Logger.Infof("Loaded information about %d application products, %d do not have repos", len(ProductToRepo), productsWithoutRepos)
	fmt.Printf("Loaded information about %d products, %d do not have repos\n", len(ProductToRepo), productsWithoutRepos)
	descriptions := make([]string, 0, len(DescriptionFrequency))
	for description := range DescriptionFrequency {
		descriptions = append(descriptions, description)
	}
	sort.SliceStable(descriptions, func(i, j int) bool {
		return DescriptionFrequency[descriptions[i]] > DescriptionFrequency[descriptions[j]]
	})
	for _, d := range descriptions {
		fmt.Printf("%s,%d\n", d, DescriptionFrequency[d])
	}
	Logger.Infof("Seen %d descriptions", len(DescriptionFrequency))
	fmt.Printf("Seen %d descriptions \n", len(DescriptionFrequency))
}
