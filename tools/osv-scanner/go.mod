module github.com/google/osv/tools/scanner

go 1.18

require (
	github.com/BurntSushi/toml v1.2.0
	github.com/CycloneDX/cyclonedx-go v0.5.0
	github.com/spdx/tools-golang v0.2.0
	github.com/urfave/cli/v2 v2.11.1
	osv-detector v0.0.0-00010101000000-000000000000
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spdx/gordf v0.0.0-20201111095634-7098f93598fb // indirect
	github.com/xrash/smetrics v0.0.0-20201216005158-039620a65673 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/xerrors v0.0.0-20191011141410-1b5146add898 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace osv-detector => github.com/g-rath/osv-detector v0.7.0
