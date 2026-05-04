package worker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func (e *Engine) populateAffectedCommitsAndTags(ctx context.Context, vuln *osvschema.Vulnerability, sourceRepo *models.SourceRepository) (models.AffectedCommitsResult, error) {
	if sourceRepo.GitAnalysis.IgnoreGit {
		return models.AffectedCommitsResult{}, nil
	}
	if e.GitterHost == "" {
		return models.AffectedCommitsResult{}, errors.New("GitterHost not set")
	}
	var allCommits [][]byte
	for _, affected := range vuln.GetAffected() {
		for _, aRange := range affected.GetRanges() {
			repo := aRange.GetRepo()
			if aRange.GetType() != osvschema.Range_GIT || repo == "" {
				continue
			}
			resp, err := fetchAffectedCommits(ctx, e.GitterClient, e.GitterHost, aRange, sourceRepo.GitAnalysis)
			if err != nil {
				return models.AffectedCommitsResult{}, err
			}
			if resp == nil {
				continue // Forbidden
			}

			applyAffectedCommitsAndTags(resp, affected, aRange)

			// Collect commits
			for _, commit := range resp.GetCommits() {
				allCommits = append(allCommits, commit.GetHash())
			}
		}
	}

	return models.AffectedCommitsResult{
		Commits: allCommits,
		Skip:    false,
	}, nil
}

func fetchAffectedCommits(ctx context.Context, client *http.Client, gitterHost string, aRange *osvschema.Range, gitAnalysis *models.GitAnalysisConfig) (*gitterpb.AffectedCommitsResponse, error) {
	req, err := newAffectedCommitsRequest(aRange, gitAnalysis)
	if err != nil {
		return nil, fmt.Errorf("failed constructing gitter request: %w", err)
	}
	reqBytes, err := proto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal gitter request proto: %w", err)
	}
	gitterURL, err := url.JoinPath(gitterHost, "affected-commits")
	if err != nil {
		return nil, fmt.Errorf("failed constructing gitter request URL: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, gitterURL, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, fmt.Errorf("failed constructing gitter request: %w", err)
	}
	httpReq.Header.Add("Content-Type", "application/x-protobuf")

	if client == nil {
		client = http.DefaultClient
	}

	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error from gitter: %w", err)
	}
	defer httpResp.Body.Close()
	if httpResp.StatusCode == http.StatusForbidden {
		return nil, nil //nolint:nilnil // repository is inacessible - somewhat expected
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gitter responded with %s", httpResp.Status)
	}
	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("errors reading gitter response: %w", err)
	}
	resp := new(gitterpb.AffectedCommitsResponse)
	if err := proto.Unmarshal(respBytes, resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal gitter response: %w", err)
	}

	return resp, nil
}

func applyAffectedCommitsAndTags(resp *gitterpb.AffectedCommitsResponse, affected *osvschema.Affected, aRange *osvschema.Range) {
	// Extract tags and add to affected.Versions
	for _, tag := range resp.GetTags() {
		exists := false
		for _, v := range affected.GetVersions() {
			if v == tag.GetLabel() {
				exists = true
				break
			}
		}
		if !exists {
			affected.Versions = append(affected.Versions, tag.GetLabel())
		}
	}

	// Extract cherry-picked events and add to aRange.Events
	for _, cherry := range resp.GetCherryPickedEvents() {
		hash := cherry.GetHash()
		eventType := cherry.GetEventType()

		exists := false
		for _, e := range aRange.GetEvents() {
			var currentHash string
			switch eventType {
			case gitterpb.EventType_INTRODUCED:
				currentHash = e.GetIntroduced()
			case gitterpb.EventType_FIXED:
				currentHash = e.GetFixed()
			case gitterpb.EventType_LIMIT:
				currentHash = e.GetLimit()
			case gitterpb.EventType_LAST_AFFECTED:
				// probably impossible, but just in case
				currentHash = e.GetLastAffected()
			}
			if currentHash == hash {
				exists = true
				break
			}
		}

		if !exists {
			var newEvent *osvschema.Event
			switch eventType {
			case gitterpb.EventType_INTRODUCED:
				newEvent = &osvschema.Event{Introduced: hash}
			case gitterpb.EventType_FIXED:
				newEvent = &osvschema.Event{Fixed: hash}
			case gitterpb.EventType_LIMIT:
				newEvent = &osvschema.Event{Limit: hash}
			case gitterpb.EventType_LAST_AFFECTED:
				// probably impossible, but just in case
				newEvent = &osvschema.Event{LastAffected: hash}
			}
			aRange.Events = append(aRange.Events, newEvent)
		}
	}
}

func newAffectedCommitsRequest(affectedRange *osvschema.Range, gitAnalysis *models.GitAnalysisConfig) (*gitterpb.AffectedCommitsRequest, error) {
	gitterReq := &gitterpb.AffectedCommitsRequest{
		Url:                         affectedRange.GetRepo(),
		ConsiderAllBranches:         gitAnalysis.ConsiderAllBranches,
		DetectCherrypicksIntroduced: gitAnalysis.DetectCherrypicks,
		DetectCherrypicksFixed:      gitAnalysis.DetectCherrypicks,
		DetectCherrypicksLimit:      gitAnalysis.DetectCherrypicks,
		Events:                      make([]*gitterpb.Event, 0, len(affectedRange.GetEvents())),
	}
	for _, event := range affectedRange.GetEvents() {
		var commit string
		var eventType gitterpb.EventType
		switch {
		case event.GetIntroduced() != "":
			commit = event.GetIntroduced()
			eventType = gitterpb.EventType_INTRODUCED
		case event.GetFixed() != "":
			commit = event.GetFixed()
			eventType = gitterpb.EventType_FIXED
		case event.GetLastAffected() != "":
			commit = event.GetLastAffected()
			eventType = gitterpb.EventType_LAST_AFFECTED
		case event.GetLimit() != "":
			commit = event.GetLimit()
			eventType = gitterpb.EventType_LIMIT
		default:
			return nil, errors.New("event does not have known field")
		}
		gitterReq.Events = append(gitterReq.Events, &gitterpb.Event{Hash: commit, EventType: eventType})
	}

	return gitterReq, nil
}
