// Package integration provides core data structures and validation for security platform integrations
package integration

import (
	"regexp"
	"time"

	"github.com/go-playground/validator/v10"
	"../common/errors"
)

var (
	// validEnvironments defines allowed deployment environments
	validEnvironments = []string{"production", "staging", "development"}

	// validAuthTypes defines supported authentication methods
	validAuthTypes = []string{"oauth2", "api_key", "basic", "certificate"}

	// validCollectionModes defines supported data collection modes
	validCollectionModes = []string{"realtime", "batch", "hybrid"}

	// namePattern defines the regex for valid integration names
	namePattern = regexp.MustCompile(`^[a-zA-Z0-9-_]{3,64}$`)

	// validate holds the validator instance
	validate = validator.New()
)

// Integration represents a security platform integration with comprehensive validation
type Integration struct {
	ID           string             `json:"id" validate:"required,uuid"`
	Name         string             `json:"name" validate:"required,min=3,max=64"`
	PlatformType string             `json:"platform_type" validate:"required"`
	Config       *IntegrationConfig `json:"config" validate:"required"`
	CreatedAt    time.Time         `json:"created_at" validate:"required"`
	UpdatedAt    time.Time         `json:"updated_at" validate:"required,gtfield=CreatedAt"`
}

// Validate performs comprehensive validation of the integration configuration
func (i *Integration) Validate() error {
	if !namePattern.MatchString(i.Name) {
		return errors.NewCLIError("E1004", "Invalid integration name format", nil)
	}

	if i.Config == nil {
		return errors.NewCLIError("E1004", "Integration configuration is required", nil)
	}

	if err := validate.Struct(i); err != nil {
		return errors.NewCLIError("E1004", "Integration validation failed", err)
	}

	if err := i.Config.Validate(); err != nil {
		return errors.WrapError(err, "Invalid integration configuration")
	}

	return nil
}

// IntegrationConfig defines configuration settings for a security platform integration
type IntegrationConfig struct {
	Environment string           `json:"environment" validate:"required"`
	Auth        *AuthConfig      `json:"auth" validate:"required"`
	Collection  *CollectionConfig `json:"collection" validate:"required"`
}

// Validate validates all integration configuration settings
func (c *IntegrationConfig) Validate() error {
	valid := false
	for _, env := range validEnvironments {
		if c.Environment == env {
			valid = true
			break
		}
	}
	if !valid {
		return errors.NewCLIError("E1004", "Invalid environment specified", nil)
	}

	if c.Auth == nil {
		return errors.NewCLIError("E1004", "Authentication configuration is required", nil)
	}

	if c.Collection == nil {
		return errors.NewCLIError("E1004", "Collection configuration is required", nil)
	}

	if err := c.Auth.Validate(); err != nil {
		return errors.WrapError(err, "Invalid authentication configuration")
	}

	if err := c.Collection.Validate(); err != nil {
		return errors.WrapError(err, "Invalid collection configuration")
	}

	return nil
}

// AuthConfig defines authentication configuration with enhanced security validation
type AuthConfig struct {
	Type           string `json:"type" validate:"required"`
	ClientID       string `json:"client_id,omitempty"`
	ClientSecret   string `json:"client_secret,omitempty"`
	APIKey         string `json:"api_key,omitempty"`
	CertificatePath string `json:"certificate_path,omitempty"`
}

// Validate performs security-focused validation of authentication configuration
func (a *AuthConfig) Validate() error {
	valid := false
	for _, authType := range validAuthTypes {
		if a.Type == authType {
			valid = true
			break
		}
	}
	if !valid {
		return errors.NewCLIError("E1004", "Invalid authentication type", nil)
	}

	switch a.Type {
	case "oauth2":
		if a.ClientID == "" || a.ClientSecret == "" {
			return errors.NewCLIError("E1004", "OAuth2 requires client ID and secret", nil)
		}
	case "api_key":
		if a.APIKey == "" {
			return errors.NewCLIError("E1004", "API key is required", nil)
		}
	case "certificate":
		if a.CertificatePath == "" {
			return errors.NewCLIError("E1004", "Certificate path is required", nil)
		}
	case "basic":
		if a.ClientID == "" || a.ClientSecret == "" {
			return errors.NewCLIError("E1004", "Basic auth requires username and password", nil)
		}
	}

	return nil
}

// CollectionConfig defines configuration for security event collection
type CollectionConfig struct {
	Mode          string   `json:"mode" validate:"required"`
	EventTypes    []string `json:"event_types" validate:"required,min=1"`
	BatchSchedule string   `json:"batch_schedule,omitempty"`
}

// Validate performs comprehensive validation of collection configuration
func (c *CollectionConfig) Validate() error {
	valid := false
	for _, mode := range validCollectionModes {
		if c.Mode == mode {
			valid = true
			break
		}
	}
	if !valid {
		return errors.NewCLIError("E1004", "Invalid collection mode", nil)
	}

	if len(c.EventTypes) == 0 {
		return errors.NewCLIError("E1004", "At least one event type must be specified", nil)
	}

	if c.Mode == "batch" || c.Mode == "hybrid" {
		if c.BatchSchedule == "" {
			return errors.NewCLIError("E1004", "Batch schedule is required for batch/hybrid mode", nil)
		}
		// Basic cron syntax validation
		if matched, _ := regexp.MatchString(`^(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)$`, c.BatchSchedule); !matched {
			return errors.NewCLIError("E1004", "Invalid batch schedule format", nil)
		}
	}

	return nil
}