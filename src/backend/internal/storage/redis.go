// Package storage provides data storage implementations for the BlackPoint Security Integration Framework
package storage

import (
	"context"
	"encoding/json"
	"time"

	"github.com/blackpoint/pkg/common" // v1.0.0
	"github.com/go-redis/redis/v8"     // v8.11.5
)

// Default configuration values
const (
	defaultTTL          = 15 * time.Minute
	defaultTimeout      = 5 * time.Second
	defaultPoolSize     = 100
	defaultDialTimeout  = 5 * time.Second
	defaultReadTimeout  = 3 * time.Second
	defaultWriteTimeout = 3 * time.Second
)

// RedisConfig holds configuration for Redis client with security settings
type RedisConfig struct {
	Addresses    []string
	Password     string
	ClusterMode  bool
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	PoolSize     int
	TLSEnabled   bool
	CertFile     string
	KeyFile      string
}

// RedisClient provides thread-safe Redis operations with cluster support
type RedisClient struct {
	cluster *redis.ClusterClient
	single  *redis.Client
	config  *RedisConfig
}

// NewRedisClient creates and initializes a new Redis client with cluster mode support
func NewRedisClient(config *RedisConfig) (*RedisClient, error) {
	if config == nil {
		return nil, common.NewError("E4001", "redis configuration is required", nil)
	}

	if len(config.Addresses) == 0 {
		return nil, common.NewError("E4001", "at least one redis address is required", nil)
	}

	// Apply defaults for unspecified configurations
	if config.DialTimeout == 0 {
		config.DialTimeout = defaultDialTimeout
	}
	if config.ReadTimeout == 0 {
		config.ReadTimeout = defaultReadTimeout
	}
	if config.WriteTimeout == 0 {
		config.WriteTimeout = defaultWriteTimeout
	}
	if config.PoolSize == 0 {
		config.PoolSize = defaultPoolSize
	}

	client := &RedisClient{
		config: config,
	}

	var err error
	if config.ClusterMode {
		err = client.initClusterClient()
	} else {
		err = client.initSingleClient()
	}

	if err != nil {
		return nil, common.WrapError(err, "failed to initialize redis client", nil)
	}

	// Verify connection
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		return nil, common.WrapError(err, "failed to ping redis", nil)
	}

	return client, nil
}

// initClusterClient initializes Redis cluster client with security settings
func (c *RedisClient) initClusterClient() error {
	opts := &redis.ClusterOptions{
		Addrs:        c.config.Addresses,
		Password:     c.config.Password,
		DialTimeout:  c.config.DialTimeout,
		ReadTimeout:  c.config.ReadTimeout,
		WriteTimeout: c.config.WriteTimeout,
		PoolSize:     c.config.PoolSize,
	}

	if c.config.TLSEnabled {
		tlsConfig, err := createTLSConfig(c.config.CertFile, c.config.KeyFile)
		if err != nil {
			return common.WrapError(err, "failed to create TLS config", nil)
		}
		opts.TLSConfig = tlsConfig
	}

	c.cluster = redis.NewClusterClient(opts)
	return nil
}

// initSingleClient initializes single Redis client with security settings
func (c *RedisClient) initSingleClient() error {
	opts := &redis.Options{
		Addr:         c.config.Addresses[0],
		Password:     c.config.Password,
		DialTimeout:  c.config.DialTimeout,
		ReadTimeout:  c.config.ReadTimeout,
		WriteTimeout: c.config.WriteTimeout,
		PoolSize:     c.config.PoolSize,
	}

	if c.config.TLSEnabled {
		tlsConfig, err := createTLSConfig(c.config.CertFile, c.config.KeyFile)
		if err != nil {
			return common.WrapError(err, "failed to create TLS config", nil)
		}
		opts.TLSConfig = tlsConfig
	}

	c.single = redis.NewClient(opts)
	return nil
}

// Set stores a value with optional TTL and JSON serialization
func (c *RedisClient) Set(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	if key == "" {
		return common.NewError("E4001", "key is required", nil)
	}

	// Serialize value to JSON
	data, err := json.Marshal(value)
	if err != nil {
		return common.WrapError(err, "failed to serialize value", nil)
	}

	// Apply default TTL if not specified
	expiration := defaultTTL
	if ttl != nil {
		expiration = *ttl
	}

	var redisErr error
	if c.cluster != nil {
		redisErr = c.cluster.Set(ctx, key, data, expiration).Err()
	} else {
		redisErr = c.single.Set(ctx, key, data, expiration).Err()
	}

	if redisErr != nil {
		return common.WrapError(redisErr, "failed to set value in redis", map[string]interface{}{
			"key": key,
		})
	}

	return nil
}

// Get retrieves and deserializes a value from Redis
func (c *RedisClient) Get(ctx context.Context, key string, value interface{}) error {
	if key == "" {
		return common.NewError("E4001", "key is required", nil)
	}

	var data string
	var err error

	if c.cluster != nil {
		data, err = c.cluster.Get(ctx, key).Result()
	} else {
		data, err = c.single.Get(ctx, key).Result()
	}

	if err == redis.Nil {
		return common.NewError("E4001", "key not found", map[string]interface{}{
			"key": key,
		})
	}

	if err != nil {
		return common.WrapError(err, "failed to get value from redis", map[string]interface{}{
			"key": key,
		})
	}

	if err := json.Unmarshal([]byte(data), value); err != nil {
		return common.WrapError(err, "failed to deserialize value", nil)
	}

	return nil
}

// Delete removes a key from Redis
func (c *RedisClient) Delete(ctx context.Context, key string) error {
	if key == "" {
		return common.NewError("E4001", "key is required", nil)
	}

	var err error
	if c.cluster != nil {
		err = c.cluster.Del(ctx, key).Err()
	} else {
		err = c.single.Del(ctx, key).Err()
	}

	if err != nil {
		return common.WrapError(err, "failed to delete key from redis", map[string]interface{}{
			"key": key,
		})
	}

	return nil
}

// Ping verifies Redis connection health
func (c *RedisClient) Ping(ctx context.Context) error {
	var err error
	if c.cluster != nil {
		err = c.cluster.Ping(ctx).Err()
	} else {
		err = c.single.Ping(ctx).Err()
	}

	if err != nil {
		return common.WrapError(err, "redis ping failed", nil)
	}

	return nil
}

// Close gracefully shuts down Redis connections
func (c *RedisClient) Close() error {
	var err error
	if c.cluster != nil {
		err = c.cluster.Close()
	} else if c.single != nil {
		err = c.single.Close()
	}

	if err != nil {
		return common.WrapError(err, "failed to close redis client", nil)
	}

	return nil
}

// createTLSConfig creates TLS configuration for secure Redis connections
func createTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, common.NewError("E4001", "certificate and key files are required for TLS", nil)
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, common.WrapError(err, "failed to load TLS certificates", nil)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:  tls.VersionTLS12,
	}, nil
}