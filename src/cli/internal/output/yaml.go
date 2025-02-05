// Package output provides formatting utilities for CLI output
package output

import (
    "bytes"
    "fmt"
    "gopkg.in/yaml.v3" // v3.0.1
    "github.com/blackpoint/cli/pkg/common/utils"
)

// YAMLOptions configures YAML formatting behavior with security and performance settings
type YAMLOptions struct {
    // Indent specifies the number of spaces for indentation
    Indent int
    // UseFlowStyle enables flow style YAML output
    UseFlowStyle bool
    // IncludeComments preserves comments in YAML output
    IncludeComments bool
    // MaxDocumentSize limits the maximum size of YAML documents in bytes
    MaxDocumentSize int
    // EnableSafeMode enables additional security measures for YAML processing
    EnableSafeMode bool
    // CustomTags defines allowed custom YAML tags
    CustomTags map[string]string
}

// DefaultYAMLOptions provides safe default configuration for YAML formatting
var DefaultYAMLOptions = YAMLOptions{
    Indent:          2,
    UseFlowStyle:    false,
    IncludeComments: false,
    MaxDocumentSize: 1048576, // 1MB
    EnableSafeMode:  true,
    CustomTags:      make(map[string]string),
}

// FormatYAML formats any data structure into a properly indented YAML string
// using safe default options
func FormatYAML(data interface{}) (string, error) {
    return FormatYAMLWithOptions(data, DefaultYAMLOptions)
}

// FormatYAMLWithOptions formats data structure to YAML with configurable formatting options
// and enhanced security measures
func FormatYAMLWithOptions(data interface{}, options YAMLOptions) (string, error) {
    // Validate input
    if data == nil {
        return "", fmt.Errorf("nil data provided")
    }

    // Validate and sanitize input using utils
    if err := utils.ValidateInput(data); err != nil {
        return "", fmt.Errorf("input validation failed: %w", err)
    }

    // Create buffer for output
    var buf bytes.Buffer

    // Configure YAML encoder with security settings
    enc := yaml.NewEncoder(&buf)
    defer enc.Close()

    // Apply indentation
    enc.SetIndent(options.Indent)

    // Configure encoder based on options
    if options.EnableSafeMode {
        // Apply security restrictions
        if err := configureSafeMode(enc); err != nil {
            return "", fmt.Errorf("failed to configure safe mode: %w", err)
        }
    }

    // Set custom style based on options
    style := yaml.Style{
        Flow: options.UseFlowStyle,
    }

    // Create node for encoding
    var node yaml.Node
    if err := node.Encode(data); err != nil {
        return "", fmt.Errorf("failed to create YAML node: %w", err)
    }
    node.Style = style.ToNodeStyle()

    // Apply size limits
    if options.MaxDocumentSize > 0 && buf.Len() > options.MaxDocumentSize {
        return "", fmt.Errorf("document exceeds maximum size of %d bytes", options.MaxDocumentSize)
    }

    // Encode data with configured options
    if err := enc.Encode(&node); err != nil {
        return "", fmt.Errorf("YAML encoding failed: %w", err)
    }

    // Perform final security validation on output
    output := buf.String()
    if err := validateYAMLOutput(output, options); err != nil {
        return "", fmt.Errorf("output validation failed: %w", err)
    }

    return output, nil
}

// ValidateYAML validates if a string contains valid YAML syntax with security checks
func ValidateYAML(yamlStr string) (bool, error) {
    if yamlStr == "" {
        return false, fmt.Errorf("empty YAML string provided")
    }

    // Create decoder with security settings
    dec := yaml.NewDecoder(bytes.NewBufferString(yamlStr))
    
    // Enable strict mode for parsing
    dec.KnownFields(true)

    // Attempt to decode YAML content
    var node yaml.Node
    if err := dec.Decode(&node); err != nil {
        return false, fmt.Errorf("YAML validation failed: %w", err)
    }

    // Perform security validation
    if err := validateYAMLSecurity(&node); err != nil {
        return false, fmt.Errorf("security validation failed: %w", err)
    }

    return true, nil
}

// configureSafeMode applies security restrictions to the YAML encoder
func configureSafeMode(enc *yaml.Encoder) error {
    // Disable arbitrary type unmarshaling
    enc.SetStrict(true)
    
    // Additional security configurations can be added here
    return nil
}

// validateYAMLOutput performs security validation on the generated YAML
func validateYAMLOutput(output string, options YAMLOptions) error {
    // Check for maximum size
    if options.MaxDocumentSize > 0 && len(output) > options.MaxDocumentSize {
        return fmt.Errorf("output exceeds maximum size")
    }

    // Validate YAML syntax
    if valid, err := ValidateYAML(output); !valid {
        return fmt.Errorf("invalid YAML output: %w", err)
    }

    return nil
}

// validateYAMLSecurity performs security checks on YAML nodes
func validateYAMLSecurity(node *yaml.Node) error {
    if node == nil {
        return nil
    }

    // Check for potentially dangerous tags
    if node.Tag != "" && !isAllowedTag(node.Tag) {
        return fmt.Errorf("unauthorized YAML tag: %s", node.Tag)
    }

    // Recursively check child nodes
    for _, child := range node.Content {
        if err := validateYAMLSecurity(child); err != nil {
            return err
        }
    }

    return nil
}

// isAllowedTag checks if a YAML tag is in the allowed list
func isAllowedTag(tag string) bool {
    allowedTags := map[string]bool{
        "!!str":    true,
        "!!int":    true,
        "!!float":  true,
        "!!bool":   true,
        "!!null":   true,
        "!!map":    true,
        "!!seq":    true,
        "!!binary": true,
    }
    return allowedTags[tag]
}