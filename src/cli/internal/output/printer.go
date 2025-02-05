// Package output provides core output printing functionality for the BlackPoint CLI
package output

import (
    "bufio"
    "fmt"
    "os"
    "sync"
    "time"

    "github.com/fatih/color" // v1.15.0
    "golang.org/x/term"
    "golang.org/x/text/width"

    "github.com/blackpoint/cli/internal/output/formatter"
    "github.com/blackpoint/cli/internal/output/table"
)

// PrintOptions defines customization options for output printing
type PrintOptions struct {
    Format        string // Output format (json, yaml, table)
    NoColor       bool   // Disable color output
    Quiet         bool   // Minimize output
    RawOutput     bool   // Skip formatting
    IncludeHeader bool   // Include headers in output
}

// ProgressOptions defines options for progress bar display
type ProgressOptions struct {
    Width           int
    SpinnerType     string
    ShowPercentage  bool
    ShowSpeed       bool
    ShowRemaining   bool
    RefreshInterval time.Duration
}

// Printer manages console output with support for different formats and styles
type Printer struct {
    output         *os.File
    colorEnabled   bool
    outputFormat   string
    writeMutex     *sync.Mutex
    bufferedOutput *bufio.Writer
    terminalWidth  int
    isRTL          bool
    resizeNotify   chan struct{}
}

// NewPrinter creates a new Printer instance with specified configuration
func NewPrinter(output *os.File, enableColor bool, enableRTL bool) (*Printer, error) {
    if output == nil {
        output = os.Stdout
    }

    // Check if output is terminal
    isTerm := term.IsTerminal(int(output.Fd()))
    if !isTerm {
        enableColor = false
    }

    // Get initial terminal width
    width, _, err := term.GetSize(int(output.Fd()))
    if err != nil {
        width = 80 // Default width
    }

    p := &Printer{
        output:         output,
        colorEnabled:   enableColor,
        outputFormat:   "text",
        writeMutex:     &sync.Mutex{},
        bufferedOutput: bufio.NewWriter(output),
        terminalWidth:  width,
        isRTL:         enableRTL,
        resizeNotify:   make(chan struct{}),
    }

    // Setup terminal resize handler
    if isTerm {
        go p.handleTerminalResize()
    }

    return p, nil
}

// PrintData prints structured data in specified format
func (p *Printer) PrintData(data interface{}, format string, options PrintOptions) error {
    if data == nil {
        return fmt.Errorf("nil data provided")
    }

    p.writeMutex.Lock()
    defer p.writeMutex.Unlock()

    var output string
    var err error

    switch format {
    case "json":
        output, err = formatter.FormatJSON(data)
    case "yaml":
        output, err = formatter.FormatYAML(data)
    case "table":
        if t, ok := data.([][]string); ok {
            tableOpts := table.TableOptions{
                Border:      true,
                CenterAlign: false,
                AutoWrap:    true,
                MinWidth:    10,
            }
            output, err = p.formatTable(t, tableOpts)
        } else {
            return fmt.Errorf("invalid data type for table format")
        }
    default:
        return fmt.Errorf("unsupported format: %s", format)
    }

    if err != nil {
        return fmt.Errorf("formatting error: %w", err)
    }

    if p.isRTL {
        output = p.handleRTLText(output)
    }

    if _, err := p.bufferedOutput.WriteString(output + "\n"); err != nil {
        return fmt.Errorf("write error: %w", err)
    }

    return p.bufferedOutput.Flush()
}

// PrintSuccess prints a success message
func (p *Printer) PrintSuccess(message string) error {
    p.writeMutex.Lock()
    defer p.writeMutex.Unlock()

    if p.colorEnabled {
        message = color.GreenString("✓ " + message)
    } else {
        message = "SUCCESS: " + message
    }

    if _, err := p.bufferedOutput.WriteString(message + "\n"); err != nil {
        return fmt.Errorf("write error: %w", err)
    }

    return p.bufferedOutput.Flush()
}

// PrintError prints an error message
func (p *Printer) PrintError(message string, err error) error {
    p.writeMutex.Lock()
    defer p.writeMutex.Unlock()

    output := message
    if err != nil {
        output = fmt.Sprintf("%s: %v", message, err)
    }

    if p.colorEnabled {
        output = color.RedString("✗ " + output)
    } else {
        output = "ERROR: " + output
    }

    if _, err := p.bufferedOutput.WriteString(output + "\n"); err != nil {
        return fmt.Errorf("write error: %w", err)
    }

    return p.bufferedOutput.Flush()
}

// PrintProgress creates and returns a progress bar
func (p *Printer) PrintProgress(total int64, description string, options ProgressOptions) (*formatter.ProgressBar, error) {
    if total <= 0 {
        return nil, fmt.Errorf("total must be positive")
    }

    if options.Width == 0 {
        options.Width = p.terminalWidth - 20 // Leave space for text
    }

    progressOpts := formatter.ProgressOptions{
        Width:           options.Width,
        Description:     description,
        ShowPercentage:  options.ShowPercentage,
        ShowSpeed:       options.ShowSpeed,
        SpinnerType:     options.SpinnerType,
        ColorEnabled:    p.colorEnabled,
        RefreshRate:     options.RefreshInterval,
        ShowRemaining:   options.ShowRemaining,
    }

    return formatter.NewProgressBar(total, progressOpts)
}

// handleTerminalResize monitors and handles terminal resize events
func (p *Printer) handleTerminalResize() {
    for {
        width, _, err := term.GetSize(int(p.output.Fd()))
        if err == nil && width != p.terminalWidth {
            p.writeMutex.Lock()
            p.terminalWidth = width
            p.writeMutex.Unlock()
            p.resizeNotify <- struct{}{}
        }
        time.Sleep(time.Second)
    }
}

// formatTable formats data as a table
func (p *Printer) formatTable(data [][]string, options table.TableOptions) (string, error) {
    t, err := table.NewTable(data[0], options) // First row as headers
    if err != nil {
        return "", err
    }

    if err := t.AddRows(data[1:]); err != nil {
        return "", err
    }

    return t.Render()
}

// handleRTLText handles right-to-left text formatting
func (p *Printer) handleRTLText(text string) string {
    if !p.isRTL {
        return text
    }

    // Use width package to handle RTL text properties
    properties := width.LookupString(text)
    if properties.Kind() == width.EastAsianWide {
        // Apply RTL formatting
        return "\u200F" + text + "\u200E" // Add RTL and LTR marks
    }
    return text
}