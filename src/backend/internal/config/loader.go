// Package config provides configuration management functionality for the BlackPoint Security Integration Framework
package config

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms" // v1.20.0
	"github.com/spf13/viper"                   // v1.15.0
	"gopkg.in/yaml.v3"                         // v3.0.1

	"../../pkg/common/errors"
	"../../pkg/common/logging"
)

// Default configuration paths and settings
var (
	defaultConfigPaths = []string{
		"./config",
		"/etc/blackpoint",
		"$HOME/.blackpoint",
	}

	configFileTypes = []string{"yaml", "yml"}
	envPrefix       = "BLACKPOINT_"
	configVersionKey = "CONFIG_VERSION"
	maxConfigCacheSize = 1024 * 1024 * 10 // 10MB cache size
)

// ConfigLoader provides enhanced configuration loading with security features
type ConfigLoader struct {
	viper      *viper.Viper
	kmsClient  *kms.Client
	cache      sync.Map
	cacheTTL   time.Duration
	environment string
	auditLogger *logging.Logger
	mu         sync.RWMutex
}

// NewConfigLoader creates a new ConfigLoader instance with security context
func NewConfigLoader(environment string) (*ConfigLoader, error) {
	v := viper.New()

	// Configure Viper settings
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	for _, path := range defaultConfigPaths {
		v.AddConfigPath(path)
	}
	for _, typ := range configFileTypes {
		v.SetConfigType(typ)
	}

	// Initialize KMS client for secure parameter handling
	kmsClient, err := initKMSClient()
	if err != nil {
		return nil, errors.WrapError(err, "failed to initialize KMS client", nil)
	}

	return &ConfigLoader{
		viper:       v,
		kmsClient:   kmsClient,
		cacheTTL:    5 * time.Minute,
		environment: environment,
		auditLogger: logging.NewLogger(),
	}, nil
}

// LoadConfig loads configuration from file and environment variables with security features
func (cl *ConfigLoader) LoadConfig(configPath string, config interface{}) error {
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Check cache first
	if cached, ok := cl.checkCache(configPath); ok {
		if err := yaml.Unmarshal(cached, config); err == nil {
			return nil
		}
	}

	// Set config file path
	cl.viper.SetConfigFile(configPath)

	// Load configuration file
	if err := cl.viper.ReadInConfig(); err != nil {
		return errors.WrapError(err, "failed to read config file", map[string]interface{}{
			"path": configPath,
		})
	}

	// Verify config version
	if err := cl.verifyConfigVersion(); err != nil {
		return err
	}

	// Get configuration as map for processing
	configMap := cl.viper.AllSettings()

	// Decrypt secure parameters
	if err := cl.decryptSecureParameters(configMap); err != nil {
		return err
	}

	// Marshal processed config back to bytes
	configBytes, err := yaml.Marshal(configMap)
	if err != nil {
		return errors.WrapError(err, "failed to marshal config", nil)
	}

	// Unmarshal into provided struct
	if err := yaml.Unmarshal(configBytes, config); err != nil {
		return errors.WrapError(err, "failed to unmarshal config", nil)
	}

	// Validate configuration
	if err := ValidateConfig(config); err != nil {
		return err
	}

	// Update cache
	cl.updateCache(configPath, configBytes)

	// Audit log the configuration load
	cl.auditLogger.Info("Configuration loaded successfully",
		"path", configPath,
		"environment", cl.environment,
		"version", configMap[configVersionKey],
	)

	return nil
}

// decryptSecureParameters decrypts sensitive configuration parameters using AWS KMS
func (cl *ConfigLoader) decryptSecureParameters(config map[string]interface{}) error {
	ctx := context.Background()

	var processValue func(interface{}) (interface{}, error)
	processValue = func(v interface{}) (interface{}, error) {
		switch value := v.(type) {
		case string:
			if isEncryptedValue(value) {
				decrypted, err := cl.decryptKMSValue(ctx, value)
				if err != nil {
					return nil, err
				}
				return decrypted, nil
			}
			return value, nil

		case map[string]interface{}:
			for k, v := range value {
				processed, err := processValue(v)
				if err != nil {
					return nil, err
				}
				value[k] = processed
			}
			return value, nil

		case []interface{}:
			for i, v := range value {
				processed, err := processValue(v)
				if err != nil {
					return nil, err
				}
				value[i] = processed
			}
			return value, nil

		default:
			return v, nil
		}
	}

	_, err := processValue(config)
	return err
}

// decryptKMSValue decrypts a KMS-encrypted value
func (cl *ConfigLoader) decryptKMSValue(ctx context.Context, value string) (string, error) {
	// Remove KMS prefix if present
	encryptedValue := stripKMSPrefix(value)

	input := &kms.DecryptInput{
		CiphertextBlob: []byte(encryptedValue),
	}

	result, err := cl.kmsClient.Decrypt(ctx, input)
	if err != nil {
		return "", errors.WrapError(err, "failed to decrypt KMS value", nil)
	}

	return string(result.Plaintext), nil
}

// verifyConfigVersion verifies the configuration version
func (cl *ConfigLoader) verifyConfigVersion() error {
	version := cl.viper.GetString(configVersionKey)
	if version == "" {
		return errors.NewError("E2001", "missing configuration version", nil)
	}

	// Version format validation could be added here
	return nil
}

// checkCache checks if a valid cached configuration exists
func (cl *ConfigLoader) checkCache(path string) ([]byte, bool) {
	if value, ok := cl.cache.Load(path); ok {
		cached := value.(cacheEntry)
		if time.Since(cached.timestamp) < cl.cacheTTL {
			return cached.data, true
		}
		cl.cache.Delete(path)
	}
	return nil, false
}

// updateCache updates the configuration cache
func (cl *ConfigLoader) updateCache(path string, data []byte) {
	cl.cache.Store(path, cacheEntry{
		data:      data,
		timestamp: time.Now(),
	})
}

// cacheEntry represents a cached configuration entry
type cacheEntry struct {
	data      []byte
	timestamp time.Time
}

// initKMSClient initializes the AWS KMS client
func initKMSClient() (*kms.Client, error) {
	// AWS KMS client initialization logic here
	// This would typically use AWS SDK v2 with proper credentials
	return nil, nil
}

// isEncryptedValue checks if a value is KMS-encrypted
func isEncryptedValue(value string) bool {
	return len(value) > 7 && value[:7] == "kms:///"
}

// stripKMSPrefix removes the KMS prefix from an encrypted value
func stripKMSPrefix(value string) string {
	if isEncryptedValue(value) {
		return value[7:]
	}
	return value
}