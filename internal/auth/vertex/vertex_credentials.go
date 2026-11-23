// Package vertex provides token storage for Google Vertex AI Gemini via service account credentials.
// It serialises service account JSON into an auth file that is consumed by the runtime executor.
package vertex

import (
	"fmt"
	"io"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
)

// VertexCredentialStorage stores the service account JSON for Vertex AI access.
// The content is persisted verbatim under the "service_account" key, together with
// helper fields for project, location and email to improve logging and discovery.
type VertexCredentialStorage struct {
	// ServiceAccount holds the parsed service account JSON content.
	ServiceAccount map[string]any `json:"service_account"`

	// ProjectID is derived from the service account JSON (project_id).
	ProjectID string `json:"project_id"`

	// Email is the client_email from the service account JSON.
	Email string `json:"email"`

	// Location optionally sets a default region (e.g., us-central1) for Vertex endpoints.
	Location string `json:"location,omitempty"`

	// Type is the provider identifier stored alongside credentials. Always "vertex".
	Type string `json:"type"`

	// Prefix optionally namespaces models for this credential (e.g., "teamA").
	// This results in model names like "teamA/gemini-2.0-flash".
	Prefix string `json:"prefix,omitempty"`

	// Metadata holds arbitrary key-value pairs injected via hooks.
	Metadata map[string]any `json:"-"`
}

// SetMetadata allows external callers to inject metadata into the storage before saving.
func (s *VertexCredentialStorage) SetMetadata(meta map[string]any) {
	s.Metadata = meta
}

// SaveTokenToFile writes the credential payload to the given file path in JSON format.
// It ensures the parent directory exists and logs the operation for transparency.
func (s *VertexCredentialStorage) SaveTokenToFile(authFilePath string) error {
	misc.LogSavingCredentials(authFilePath)
	if s == nil {
		return fmt.Errorf("vertex credential: storage is nil")
	}
	if s.ServiceAccount == nil {
		return fmt.Errorf("vertex credential: service account content is empty")
	}
	// Ensure we tag the file with the provider type.
	s.Type = "vertex"

	data, errMerge := misc.MergeMetadata(s, s.Metadata)
	if errMerge != nil {
		return fmt.Errorf("vertex credential: merge metadata failed: %w", errMerge)
	}

	return misc.WritePrivateCredential(authFilePath, func(w io.Writer) error {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(data)
	})
}
