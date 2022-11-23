package main

import (
	"context"
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"golang.org/x/exp/slices"
)

type CPEDict struct {
	XMLName  xml.Name  `xml:cpe-list`
	CPEItems []CPEItem `xml:"cpe-item"`
}

type CPEItem struct {
	XMLName    xml.Name    `xml:"cpe-item",json:"-"`
	Name       string      `xml:"name,attr",json:"name"`
	Title      string      `xml:"title",json:"title"`
	References []Reference `xml:"references>reference",json:"references"`
	CPE23      CPE23Item   `xml:"cpe23-item",json:"cpe23-item"`
}

type Reference struct {
	URL         string `xml:"href,attr",json:"URL"`
	Description string `xml:",chardata",json:"description"`
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
		"Change Log",
		"Version information via GitHub",
		"product version information",
		"Version",
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
		Logger.Fatalf("Failed to load %s: %v", CPEDictionaryFile, err)
	}
	ProductToRepo := make(map[string]string)
	Descriptions := make(map[string]bool)
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
		for _, r := range c.References {
			Descriptions[r.Description] = true
			repo, err := cves.Repo(r.URL)
			if err != nil {
				Logger.Infof("Disregarding %q for %q (%s) because %v", r.URL, CPE.Product, r.Description, err)
				continue
			}
			if !slices.Contains(ValidDescriptions, r.Description) {
				Logger.Infof("Disregarding %q for %q (%s)", r.URL, CPE.Product, r.Description)
				continue
			}
			Logger.Infof("Liking %q for %q (%s)", repo, CPE.Product, r.Description)
			// TODO(apollock): optimisation: check if key already present, flag differing value
			ProductToRepo[CPE.Product] = repo
		}
	}
	Logger.Infof("Loaded information about %d products", len(ProductToRepo))
	fmt.Printf("Loaded information about %d products\n", len(ProductToRepo))
	Logger.Infof("Seen %d descriptions", len(Descriptions))
	fmt.Printf("Seen %d descriptions \n", len(Descriptions))
	for product, repo := range ProductToRepo {
		fmt.Printf("%s -> %s\n", product, repo)
	}
	for description, _ := range Descriptions {
		fmt.Printf("%s\n", description)
	}
}
