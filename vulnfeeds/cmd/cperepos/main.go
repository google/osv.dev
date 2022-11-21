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
	"github.com/google/osv/vulnfeeds/utility"
)

type CPEDict struct {
	XMLName  xml.Name  `xml:cpe-list`
	CPEItems []CPEItem `xml:"cpe-item"`
}

type CPEItem struct {
	XMLName    xml.Name    `xml:"cpe-item"`
	Name       string      `xml:"name,attr"`
	Title      string      `xml:"title"`
	References []Reference `xml:"references"`
	CPE23      CPE23s      `xml:"cpe23-item"`
}

type Reference struct {
	Href          string `xml:"href,attr"`
	ReferenceType string `xml:"reference"`
}

type CPE23s struct {
	XMLName xml.Name `xml:"cpe23-item"`
	Name    string   `xml:"name,attr"`
}

const (
	CPEDictionaryDefault = "cve_jsons/nvdcpematch-1.0.json"
	projectId            = "oss-vdb"
)

var (
	Logger            utility.LoggerWrapper
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
	fmt.Printf("%#v", CPEDictionary.CPEItems[0])
}
