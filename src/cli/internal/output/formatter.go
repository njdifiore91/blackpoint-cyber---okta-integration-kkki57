// Package output provides core output formatting functionality for the BlackPoint CLI
package output

import (
    "bytes"
    "encoding/json"
    "fmt"
    "strings"
    "sync"
    "time"

    "github.com/fatih/color"
    "github.com/schollz/progressbar/v3"
    "github.com/blackpoint/cli/pkg/common/utils"
)

// TableOptions configures table formatting behavior
type TableOptions struct {
    Border         bool              // Enable table borders
    CenterAlign    bool              // Center-align content
    MaxWidth       int               // Maximum table width
    AutoMerge      bool              // Merge identical adjacent cells
    ColorEnabled   bool              // Enable ANSI colors
    ColorScheme    map[string]string // Custom color mappings
    MinColumnWidth int               // Minimum column width
    WrapText       bool              // Enable text wrapping
}

// ProgressOptions configures progress bar behavior
type ProgressOptions struct {
    Width            int           // Progress bar width
    Description      string        // Progress description
    ShowPercentage   bool         // Show percentage complete
    ShowSpeed        bool         // Show processing speed
    SpinnerType      string       // Spinner animation type
    ColorEnabled     bool         // Enable ANSI colors
    RefreshRate      time.Duration // Refresh rate
    ShowRemainingTime bool         // Show estimated time remaining
}

// JSONOptions configures JSON formatting behavior
type JSONOptions struct {
    Indent      string // Indentation string
    EscapeHTML  bool   // Escape HTML characters
    SortKeys    bool   // Sort object keys
    MaxDepth    int    // Maximum nesting depth
}

var (
    // Default color scheme
    defaultColorScheme = map[string]string{
        "header":  "cyan",
        "border":  "white",
        "success": "green",
        "error":   "red",
        "warning": "yellow",
    }

    // Buffer pool for memory optimization
    bufferPool = sync.Pool{
        New: func() interface{} {
            return new(bytes.Buffer)
        },
    }
)

// FormatJSON formats data as an indented JSON string
func FormatJSON(data interface{}, options *JSONOptions) (string, error) {
    if data == nil {
        return "", fmt.Errorf("nil data provided")
    }

    if options == nil {
        options = &JSONOptions{
            Indent:     "  ",
            EscapeHTML: true,
            SortKeys:   true,
            MaxDepth:   10,
        }
    }

    // Get buffer from pool
    buf := bufferPool.Get().(*bytes.Buffer)
    buf.Reset()
    defer bufferPool.Put(buf)

    encoder := json.NewEncoder(buf)
    encoder.SetIndent("", options.Indent)
    encoder.SetEscapeHTML(options.EscapeHTML)

    if err := encoder.Encode(data); err != nil {
        return "", fmt.Errorf("JSON encoding failed: %w", err)
    }

    return strings.TrimSpace(buf.String()), nil
}

// FormatTable formats data as an ASCII table with optional ANSI colors
func FormatTable(headers []string, data [][]string, options TableOptions) (string, error) {
    if len(headers) == 0 || len(data) == 0 {
        return "", fmt.Errorf("empty headers or data provided")
    }

    // Apply default color scheme if enabled but not specified
    if options.ColorEnabled && options.ColorScheme == nil {
        options.ColorScheme = defaultColorScheme
    }

    // Get buffer from pool
    buf := bufferPool.Get().(*bytes.Buffer)
    buf.Reset()
    defer bufferPool.Put(buf)

    // Calculate column widths
    colWidths := make([]int, len(headers))
    for i, header := range headers {
        colWidths[i] = len(header)
    }
    for _, row := range data {
        for i, cell := range row {
            if i < len(colWidths) && len(cell) > colWidths[i] {
                colWidths[i] = len(cell)
            }
        }
    }

    // Apply minimum column width if specified
    if options.MinColumnWidth > 0 {
        for i := range colWidths {
            if colWidths[i] < options.MinColumnWidth {
                colWidths[i] = options.MinColumnWidth
            }
        }
    }

    // Write table headers
    if options.Border {
        writeBorder(buf, colWidths, options)
    }
    writeRow(buf, headers, colWidths, options, true)
    if options.Border {
        writeBorder(buf, colWidths, options)
    }

    // Write table data
    for _, row := range data {
        writeRow(buf, row, colWidths, options, false)
        if options.Border {
            writeBorder(buf, colWidths, options)
        }
    }

    return buf.String(), nil
}

// NewProgressBar creates a new progress bar with the specified options
func NewProgressBar(total int64, options ProgressOptions) *progressbar.ProgressBar {
    return progressbar.NewOptions64(total,
        progressbar.OptionSetWidth(options.Width),
        progressbar.OptionSetDescription(options.Description),
        progressbar.OptionShowBytes(true),
        progressbar.OptionSetPredictTime(options.ShowRemainingTime),
        progressbar.OptionShowCount(),
        progressbar.OptionSpinnerType(getSpinnerType(options.SpinnerType)),
        progressbar.OptionSetTheme(progressbar.Theme{
            Saucer:        "=",
            SaucerHead:    ">",
            SaucerPadding: " ",
            BarStart:      "[",
            BarEnd:        "]",
        }),
    )
}

// Helper functions

func writeBorder(buf *bytes.Buffer, colWidths []int, options TableOptions) {
    if options.ColorEnabled {
        buf.WriteString(color.New(getColorAttribute(options.ColorScheme["border"])).Sprint("+"))
    } else {
        buf.WriteString("+")
    }
    
    for _, width := range colWidths {
        buf.WriteString(strings.Repeat("-", width+2))
        buf.WriteString("+")
    }
    buf.WriteString("\n")
}

func writeRow(buf *bytes.Buffer, cells []string, colWidths []int, options TableOptions, isHeader bool) {
    if options.Border {
        buf.WriteString("| ")
    }

    for i, cell := range cells {
        if i < len(colWidths) {
            content := cell
            if options.WrapText && len(content) > colWidths[i] {
                content = content[:colWidths[i]-3] + "..."
            }
            
            if options.ColorEnabled {
                colorKey := "header"
                if !isHeader {
                    colorKey = getContentColorKey(cell)
                }
                content = color.New(getColorAttribute(options.ColorScheme[colorKey])).Sprint(content)
            }

            if options.CenterAlign {
                padding := colWidths[i] - len(cell)
                leftPad := padding / 2
                rightPad := padding - leftPad
                buf.WriteString(strings.Repeat(" ", leftPad))
                buf.WriteString(content)
                buf.WriteString(strings.Repeat(" ", rightPad))
            } else {
                buf.WriteString(content)
                buf.WriteString(strings.Repeat(" ", colWidths[i]-len(cell)))
            }
            
            if options.Border {
                buf.WriteString(" | ")
            } else {
                buf.WriteString("  ")
            }
        }
    }
    buf.WriteString("\n")
}

func getColorAttribute(colorName string) color.Attribute {
    switch strings.ToLower(colorName) {
    case "red":
        return color.FgRed
    case "green":
        return color.FgGreen
    case "yellow":
        return color.FgYellow
    case "blue":
        return color.FgBlue
    case "magenta":
        return color.FgMagenta
    case "cyan":
        return color.FgCyan
    case "white":
        return color.FgWhite
    default:
        return color.FgWhite
    }
}

func getContentColorKey(content string) string {
    switch {
    case strings.Contains(strings.ToLower(content), "error"):
        return "error"
    case strings.Contains(strings.ToLower(content), "warn"):
        return "warning"
    case strings.Contains(strings.ToLower(content), "success"):
        return "success"
    default:
        return "border"
    }
}

func getSpinnerType(spinnerType string) int {
    switch strings.ToLower(spinnerType) {
    case "dot":
        return 1
    case "line":
        return 2
    case "minidot":
        return 3
    default:
        return 1
    }
}