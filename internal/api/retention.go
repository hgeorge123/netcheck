package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hgeorge123/netcheck/internal/probes"
	"github.com/hgeorge123/netcheck/internal/store"
)

// maxRetentionDays bounds both retention periods (about ten years).
const maxRetentionDays = 3650

// RetentionSettings holds how long test output and metadata are kept. The
// Helm values seed it on the first start; afterwards administrators change it
// in the web and the database copy wins.
type RetentionSettings struct {
	mu           sync.RWMutex
	outputDays   int
	metadataDays int
	updatedAt    time.Time
	updatedBy    string
}

// NewRetentionSettings builds a holder that is not backed by the database.
func NewRetentionSettings(outputDays, metadataDays int) *RetentionSettings {
	return &RetentionSettings{outputDays: outputDays, metadataDays: metadataDays}
}

// LoadRetention returns the stored retention, saving the seed (Helm values)
// on the first start.
func LoadRetention(ctx context.Context, st *store.Store, outputDays, metadataDays int, now time.Time) (*RetentionSettings, error) {
	h := NewRetentionSettings(outputDays, metadataDays)
	h.updatedAt, h.updatedBy = now, SeedPolicyActor
	stored, err := st.GetRetention(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
		details, _ := json.Marshal(map[string]int{"outputDays": outputDays, "metadataDays": metadataDays})
		ev := store.AuditEvent{ActorID: "system:helm", Action: "retention.seed", Outcome: "success", DetailsJSON: string(details)}
		if err := st.SaveRetention(ctx, store.StoredRetention{OutputDays: outputDays, MetadataDays: metadataDays, UpdatedAt: now, UpdatedBy: SeedPolicyActor}, ev); err != nil {
			return nil, fmt.Errorf("seed retention: %w", err)
		}
		return h, nil
	case err != nil:
		return nil, fmt.Errorf("load retention: %w", err)
	}
	if len(validateRetention(stored.OutputDays, stored.MetadataDays)) > 0 {
		return nil, fmt.Errorf("stored retention is invalid: outputDays=%d metadataDays=%d", stored.OutputDays, stored.MetadataDays)
	}
	h.outputDays, h.metadataDays, h.updatedAt, h.updatedBy = stored.OutputDays, stored.MetadataDays, stored.UpdatedAt, stored.UpdatedBy
	return h, nil
}

// Days returns the current retention periods.
func (h *RetentionSettings) Days() (outputDays, metadataDays int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.outputDays, h.metadataDays
}

func (h *RetentionSettings) set(outputDays, metadataDays int, at time.Time, by string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.outputDays, h.metadataDays, h.updatedAt, h.updatedBy = outputDays, metadataDays, at, by
}

// validateRetention applies the same rules as the configuration loader.
func validateRetention(outputDays, metadataDays int) []probes.FieldError {
	var errs []probes.FieldError
	if outputDays < 1 || outputDays > maxRetentionDays {
		errs = append(errs, probes.FieldError{Field: "outputDays", Code: "invalid_days", Message: fmt.Sprintf("between 1 and %d days", maxRetentionDays)})
	}
	if metadataDays < 1 || metadataDays > maxRetentionDays {
		errs = append(errs, probes.FieldError{Field: "metadataDays", Code: "invalid_days", Message: fmt.Sprintf("between 1 and %d days", maxRetentionDays)})
	} else if metadataDays < outputDays {
		errs = append(errs, probes.FieldError{Field: "metadataDays", Code: "metadata_shorter_than_output", Message: "must be greater than or equal to outputDays"})
	}
	return errs
}

type retentionView struct {
	OutputDays   int       `json:"outputDays"`
	MetadataDays int       `json:"metadataDays"`
	UpdatedAt    time.Time `json:"updatedAt"`
	UpdatedBy    string    `json:"updatedBy"`
}

func (s *Server) retentionView() retentionView {
	s.Retention.mu.RLock()
	defer s.Retention.mu.RUnlock()
	return retentionView{OutputDays: s.Retention.outputDays, MetadataDays: s.Retention.metadataDays,
		UpdatedAt: s.Retention.updatedAt, UpdatedBy: s.Retention.updatedBy}
}

func (s *Server) adminRetention(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.retentionView())
}

func (s *Server) adminSetRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OutputDays   int `json:"outputDays"`
		MetadataDays int `json:"metadataDays"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_json", err.Error(), nil)
		return
	}
	if errs := validateRetention(req.OutputDays, req.MetadataDays); len(errs) > 0 {
		writeError(w, r, http.StatusBadRequest, "validation_failed", "the retention is not valid", errs)
		return
	}
	id := identity(r)
	beforeOutput, beforeMetadata := s.Retention.Days()
	details, _ := json.Marshal(map[string]any{
		"before": map[string]int{"outputDays": beforeOutput, "metadataDays": beforeMetadata},
		"after":  map[string]int{"outputDays": req.OutputDays, "metadataDays": req.MetadataDays},
	})
	now := time.Now()
	ev := store.AuditEvent{ActorID: id.ID, Action: "retention.update", Outcome: "success", RequestID: RequestID(r.Context()), DetailsJSON: string(details)}
	if err := s.Store.SaveRetention(r.Context(), store.StoredRetention{OutputDays: req.OutputDays, MetadataDays: req.MetadataDays, UpdatedAt: now, UpdatedBy: id.Username}, ev); err != nil {
		s.Log.Error("save retention failed", "request_id", RequestID(r.Context()), "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal", "could not save the retention", nil)
		return
	}
	s.Retention.set(req.OutputDays, req.MetadataDays, now, id.Username)
	s.Log.Info("retention updated", "request_id", RequestID(r.Context()), "actor", id.Username,
		"output_days", req.OutputDays, "metadata_days", req.MetadataDays)
	writeJSON(w, http.StatusOK, s.retentionView())
}
