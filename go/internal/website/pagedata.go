package website

import "html/template"

// BasePageData contains common fields required by the base.html layout template.
type BasePageData struct {
	ActiveSection     string
	DisableTurboCache bool
}

// EcosystemDisplay holds pre-calculated bubble data for ecosystem vulnerability counts on the home page.
type EcosystemDisplay struct {
	Name       string
	Count      int
	Radius     float64
	TooltipTop float64
}

// HomePageData represents the data context passed to home.html template.
type HomePageData struct {
	BasePageData

	Ecosystems []EcosystemDisplay
}

// NotFoundPageData represents the data context passed to 404.html template.
type NotFoundPageData struct {
	BasePageData

	FailedImportVulnID string
}

// BlogPageData represents the data context passed to blog.html template.
type BlogPageData struct {
	BasePageData

	Index template.HTML
}

// BlogPostPageData represents the data context passed to blog_post.html template.
type BlogPostPageData struct {
	BasePageData

	Content template.HTML
}

// LinterPageData represents the data context passed to linter.html template.
type LinterPageData struct {
	BasePageData
}
