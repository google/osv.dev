package main

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type updateField int

const (
	updateFieldAlias updateField = iota
	updateFieldUpstream
	updateFieldRelated
)

type Update struct {
	ID        string
	Timestamp time.Time
	Field     updateField
	Value     any
}

type Updater struct {
	Ch chan Update
	wg sync.WaitGroup
}

func NewUpdater(ctx context.Context) *Updater {
	u := &Updater{Ch: make(chan Update)}
	u.wg.Go(func() { u.run(ctx) })

	return u
}

func (u *Updater) run(ctx context.Context) {
	allUpdates := make(map[string][]Update)
	for {
		select {
		case <-ctx.Done():
			logger.Info("updater context cancelled")
			return
		case update, ok := <-u.Ch:
			if ok {
				allUpdates[update.ID] = append(allUpdates[update.ID], update)
				continue
			}
			// Channel was closed, collate updates and write
			for id, updates := range allUpdates {
				// TODO: Get the vulnerability from GCS
				v := &osvschema.Vulnerability{}
				v.Id = id
				hasUpdates := false
				var modified time.Time
				for _, u := range updates {
					switch u.Field {
					case updateFieldAlias:
						val, ok := u.Value.([]string)
						if !ok {
							logger.Error("updated aliases are not []string", slog.String("id", id))
							continue
						}
						if slices.Compare(v.Aliases, val) == 0 {
							// No actual changes, do not update
							continue
						}
						hasUpdates = true
						v.Aliases = val
						if u.Timestamp.After(modified) {
							modified = u.Timestamp
						}
					default:
						logger.Error("unsupported update field", slog.Any("updateField", u.Field), slog.String("id", id))

					}
				}
				if !hasUpdates {
					continue
				}
				v.Modified = timestamppb.New(modified)
				logger.Info("updating vuln", slog.Any("vuln", v))
			}
			return
		}
	}
}

func (u *Updater) Finish() {
	close(u.Ch)
	u.wg.Wait()
}
