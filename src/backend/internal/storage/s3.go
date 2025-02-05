// Package storage provides S3-based storage operations for the BlackPoint Security Integration Framework
package storage

import (
    "bytes"
    "compress/gzip"
    "context"
    "io"
    "time"

    "github.com/aws/aws-sdk-go-v2/aws"         // v1.21.0
    "github.com/aws/aws-sdk-go-v2/config"      // v1.21.0
    "github.com/aws/aws-sdk-go-v2/service/s3"  // v1.21.0
    "github.com/aws/aws-sdk-go-v2/service/kms" // v1.21.0
    
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
)

const (
    defaultBucketPrefix = "blackpoint-security-"
    defaultRegion      = "us-west-2"
    defaultKmsKeyAlias = "alias/blackpoint-security"
)

// S3Config contains configuration for the S3 client
type S3Config struct {
    Region            string
    BucketPrefix      string
    KmsKeyAlias       string
    RetentionPeriods  map[string]int
    EnableCompression bool
    NetworkTimeout    time.Duration
    RetryConfig      *RetryConfig
    MetricsEnabled   bool
    EncryptionContext map[string]string
}

// RetryConfig defines retry behavior for S3 operations
type RetryConfig struct {
    MaxRetries      int
    RetryInterval   time.Duration
    BackoffMultiplier float64
}

// S3Client handles S3 operations with encryption and lifecycle management
type S3Client struct {
    s3Client        *s3.Client
    kmsClient       *kms.Client
    config          *S3Config
    ctx             context.Context
}

// NewS3Client creates a new S3 client instance
func NewS3Client(cfg *S3Config) (*S3Client, error) {
    if cfg == nil {
        cfg = &S3Config{
            Region:            defaultRegion,
            BucketPrefix:      defaultBucketPrefix,
            KmsKeyAlias:       defaultKmsKeyAlias,
            EnableCompression: true,
            NetworkTimeout:    30 * time.Second,
            RetentionPeriods: map[string]int{
                "bronze": 30,  // 30 days
                "silver": 90,  // 90 days
                "gold":   365, // 365 days
            },
        }
    }

    // Load AWS configuration
    awsCfg, err := config.LoadDefaultConfig(context.Background(),
        config.WithRegion(cfg.Region),
        config.WithRetryMode(aws.RetryModeStandard),
    )
    if err != nil {
        return nil, errors.WrapError(err, "failed to load AWS config", nil)
    }

    // Create clients
    s3Client := s3.NewFromConfig(awsCfg)
    kmsClient := kms.NewFromConfig(awsCfg)

    client := &S3Client{
        s3Client:  s3Client,
        kmsClient: kmsClient,
        config:    cfg,
        ctx:       context.Background(),
    }

    // Validate access and setup
    if err := client.validateAccess(); err != nil {
        return nil, err
    }

    return client, nil
}

// PutObject stores an object in S3 with encryption and compression
func (c *S3Client) PutObject(bucket, key string, data []byte) error {
    ctx, cancel := context.WithTimeout(c.ctx, c.config.NetworkTimeout)
    defer cancel()

    // Compress data if enabled
    var contentEncoding string
    if c.config.EnableCompression {
        var buf bytes.Buffer
        gw := gzip.NewWriter(&buf)
        if _, err := gw.Write(data); err != nil {
            return errors.WrapError(err, "failed to compress data", nil)
        }
        if err := gw.Close(); err != nil {
            return errors.WrapError(err, "failed to finalize compression", nil)
        }
        data = buf.Bytes()
        contentEncoding = "gzip"
    }

    // Generate KMS encryption context
    encryptionContext := map[string]string{
        "bucket": bucket,
        "key":    key,
    }
    for k, v := range c.config.EncryptionContext {
        encryptionContext[k] = v
    }

    // Upload object with server-side encryption
    _, err := c.s3Client.PutObject(ctx, &s3.PutObjectInput{
        Bucket:               aws.String(bucket),
        Key:                  aws.String(key),
        Body:                 bytes.NewReader(data),
        ContentEncoding:      aws.String(contentEncoding),
        ServerSideEncryption: aws.String("aws:kms"),
        SSEKMSKeyId:         aws.String(c.config.KmsKeyAlias),
        Metadata: map[string]string{
            "encryption-context": "true",
        },
    })

    if err != nil {
        return errors.WrapError(err, "failed to upload object", map[string]interface{}{
            "bucket": bucket,
            "key":    key,
        })
    }

    logging.Info("Successfully uploaded object to S3",
        zap.String("bucket", bucket),
        zap.String("key", key),
        zap.Int("size", len(data)),
    )

    return nil
}

// GetObject retrieves and decrypts an object from S3
func (c *S3Client) GetObject(bucket, key string) ([]byte, error) {
    ctx, cancel := context.WithTimeout(c.ctx, c.config.NetworkTimeout)
    defer cancel()

    // Download object
    result, err := c.s3Client.GetObject(ctx, &s3.GetObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String(key),
    })
    if err != nil {
        return nil, errors.WrapError(err, "failed to download object", map[string]interface{}{
            "bucket": bucket,
            "key":    key,
        })
    }
    defer result.Body.Close()

    // Read object data
    data, err := io.ReadAll(result.Body)
    if err != nil {
        return nil, errors.WrapError(err, "failed to read object data", nil)
    }

    // Decompress if necessary
    if aws.ToString(result.ContentEncoding) == "gzip" {
        gr, err := gzip.NewReader(bytes.NewReader(data))
        if err != nil {
            return nil, errors.WrapError(err, "failed to create gzip reader", nil)
        }
        defer gr.Close()

        data, err = io.ReadAll(gr)
        if err != nil {
            return nil, errors.WrapError(err, "failed to decompress data", nil)
        }
    }

    logging.Info("Successfully retrieved object from S3",
        zap.String("bucket", bucket),
        zap.String("key", key),
        zap.Int("size", len(data)),
    )

    return data, nil
}

// DeleteObject deletes an object from S3
func (c *S3Client) DeleteObject(bucket, key string) error {
    ctx, cancel := context.WithTimeout(c.ctx, c.config.NetworkTimeout)
    defer cancel()

    _, err := c.s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
        Bucket: aws.String(bucket),
        Key:    aws.String(key),
    })

    if err != nil {
        return errors.WrapError(err, "failed to delete object", map[string]interface{}{
            "bucket": bucket,
            "key":    key,
        })
    }

    logging.Info("Successfully deleted object from S3",
        zap.String("bucket", bucket),
        zap.String("key", key),
    )

    return nil
}

// validateAccess verifies S3 and KMS access permissions
func (c *S3Client) validateAccess() error {
    ctx, cancel := context.WithTimeout(c.ctx, c.config.NetworkTimeout)
    defer cancel()

    // Verify KMS key access
    _, err := c.kmsClient.DescribeKey(ctx, &kms.DescribeKeyInput{
        KeyId: aws.String(c.config.KmsKeyAlias),
    })
    if err != nil {
        return errors.WrapError(err, "failed to validate KMS key access", nil)
    }

    // Verify bucket access for each tier
    tiers := []string{"bronze", "silver", "gold"}
    for _, tier := range tiers {
        bucket := c.config.BucketPrefix + tier
        _, err := c.s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
            Bucket: aws.String(bucket),
        })
        if err != nil {
            return errors.WrapError(err, "failed to validate bucket access", map[string]interface{}{
                "bucket": bucket,
                "tier":   tier,
            })
        }

        if err := c.configureBucket(bucket); err != nil {
            return err
        }
    }

    return nil
}

// configureBucket sets up bucket encryption and lifecycle policies
func (c *S3Client) configureBucket(bucket string) error {
    ctx, cancel := context.WithTimeout(c.ctx, c.config.NetworkTimeout)
    defer cancel()

    // Configure server-side encryption
    _, err := c.s3Client.PutBucketEncryption(ctx, &s3.PutBucketEncryptionInput{
        Bucket: aws.String(bucket),
        ServerSideEncryptionConfiguration: &s3.ServerSideEncryptionConfiguration{
            Rules: []s3.ServerSideEncryptionRule{
                {
                    ApplyServerSideEncryptionByDefault: &s3.ServerSideEncryptionByDefault{
                        SSEAlgorithm:   aws.String("aws:kms"),
                        KMSMasterKeyID: aws.String(c.config.KmsKeyAlias),
                    },
                },
            },
        },
    })
    if err != nil {
        return errors.WrapError(err, "failed to configure bucket encryption", map[string]interface{}{
            "bucket": bucket,
        })
    }

    // Configure lifecycle rules
    tier := bucket[len(c.config.BucketPrefix):]
    retentionDays := c.config.RetentionPeriods[tier]
    if retentionDays > 0 {
        _, err = c.s3Client.PutBucketLifecycleConfiguration(ctx, &s3.PutBucketLifecycleConfigurationInput{
            Bucket: aws.String(bucket),
            LifecycleConfiguration: &s3.BucketLifecycleConfiguration{
                Rules: []s3.LifecycleRule{
                    {
                        ID:     aws.String(fmt.Sprintf("%s-retention", tier)),
                        Status: aws.String("Enabled"),
                        Expiration: &s3.LifecycleExpiration{
                            Days: aws.Int32(int32(retentionDays)),
                        },
                    },
                },
            },
        })
        if err != nil {
            return errors.WrapError(err, "failed to configure lifecycle rules", map[string]interface{}{
                "bucket": bucket,
                "tier":   tier,
            })
        }
    }

    return nil
}