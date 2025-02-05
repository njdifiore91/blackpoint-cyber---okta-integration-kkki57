// Package output provides table rendering functionality for the BlackPoint CLI
package output

import (
    "fmt"
    "strings"
    "unicode/utf8"
    
    "github.com/olekukonko/tablewriter"
    "golang.org/x/term"
    
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/common/utils"
)

// TableOptions defines customization options for table rendering
type TableOptions struct {
    Border         bool
    CenterAlign    bool
    AutoMerge      bool
    RowLine        bool
    AutoWrap       bool
    MinWidth       int
    MaxColWidth    int
}

// CellFormatter defines a function type for custom cell formatting
type CellFormatter func(string) string

// Table manages table rendering with customizable formatting options
type Table struct {
    writer        *tablewriter.Table
    headers       []string
    rows          [][]string
    options       TableOptions
    terminalWidth int
    formatters    map[string]CellFormatter
}

// NewTable creates a new Table instance with specified headers and options
func NewTable(headers []string, options TableOptions) (*Table, error) {
    if len(headers) == 0 {
        return nil, errors.NewCLIError("E1004", "table headers cannot be empty", nil)
    }

    // Get terminal width
    width, _, err := term.GetSize(0)
    if err != nil {
        width = 80 // Default width if terminal size cannot be determined
    }

    table := &Table{
        headers:       headers,
        options:      options,
        terminalWidth: width,
        formatters:   make(map[string]CellFormatter),
    }

    // Initialize tablewriter
    table.writer = tablewriter.NewWriter(strings.Builder{})
    table.configureWriter()
    table.writer.SetHeader(headers)

    return table, nil
}

// AddRow adds a new row to the table with support for cell merging
func (t *Table) AddRow(row []string) error {
    if len(row) != len(t.headers) {
        return errors.NewCLIError("E1004", 
            fmt.Sprintf("row length %d does not match header length %d", len(row), len(t.headers)), 
            nil)
    }

    // Apply formatters to cells
    formattedRow := make([]string, len(row))
    for i, cell := range row {
        if formatter, exists := t.formatters[t.headers[i]]; exists {
            formattedRow[i] = formatter(cell)
        } else {
            formattedRow[i] = cell
        }
    }

    t.rows = append(t.rows, formattedRow)
    t.writer.Append(formattedRow)
    return nil
}

// AddRows adds multiple rows to the table with batch processing
func (t *Table) AddRows(rows [][]string) error {
    if len(rows) == 0 {
        return nil
    }

    for _, row := range rows {
        if err := t.AddRow(row); err != nil {
            return err
        }
    }
    return nil
}

// SetColumnAlignment sets alignment for specific columns
func (t *Table) SetColumnAlignment(alignments []int) error {
    if len(alignments) != len(t.headers) {
        return errors.NewCLIError("E1004", 
            "alignment count does not match header count", 
            nil)
    }
    t.writer.SetColumnAlignment(alignments)
    return nil
}

// SetFormatter sets a custom formatter for a specific column
func (t *Table) SetFormatter(column string, formatter CellFormatter) error {
    if !t.hasHeader(column) {
        return errors.NewCLIError("E1004", 
            fmt.Sprintf("column %s not found in headers", column), 
            nil)
    }
    t.formatters[column] = formatter
    return nil
}

// Render renders the table as a formatted string
func (t *Table) Render() (string, error) {
    // Adjust column widths based on terminal size
    colWidths := t.calculateColumnWidths()
    t.writer.SetColumnWidths(colWidths)

    var output strings.Builder
    t.writer.SetOutput(&output)
    t.writer.Render()
    return output.String(), nil
}

// configureWriter sets up the tablewriter with the specified options
func (t *Table) configureWriter() {
    t.writer.SetBorder(t.options.Border)
    t.writer.SetAutoMergeCells(t.options.AutoMerge)
    t.writer.SetRowLine(t.options.RowLine)
    t.writer.SetAutoWrapText(t.options.AutoWrap)

    if t.options.CenterAlign {
        alignments := make([]int, len(t.headers))
        for i := range alignments {
            alignments[i] = tablewriter.ALIGN_CENTER
        }
        t.writer.SetColumnAlignment(alignments)
    }
}

// calculateColumnWidths determines optimal column widths based on content and terminal size
func (t *Table) calculateColumnWidths() []int {
    availableWidth := t.terminalWidth
    if t.options.Border {
        availableWidth -= (len(t.headers) + 1) // Account for borders
    }

    // Calculate content widths
    maxWidths := make([]int, len(t.headers))
    for i, header := range t.headers {
        maxWidths[i] = utf8.RuneCountInString(header)
        for _, row := range t.rows {
            width := utf8.RuneCountInString(row[i])
            if width > maxWidths[i] {
                maxWidths[i] = width
            }
        }
    }

    // Apply constraints
    totalWidth := 0
    for i := range maxWidths {
        if t.options.MaxColWidth > 0 && maxWidths[i] > t.options.MaxColWidth {
            maxWidths[i] = t.options.MaxColWidth
        }
        if maxWidths[i] < t.options.MinWidth {
            maxWidths[i] = t.options.MinWidth
        }
        totalWidth += maxWidths[i]
    }

    // Adjust if total width exceeds terminal
    if totalWidth > availableWidth {
        ratio := float64(availableWidth) / float64(totalWidth)
        for i := range maxWidths {
            maxWidths[i] = int(float64(maxWidths[i]) * ratio)
            if maxWidths[i] < t.options.MinWidth {
                maxWidths[i] = t.options.MinWidth
            }
        }
    }

    return maxWidths
}

// hasHeader checks if a column exists in headers
func (t *Table) hasHeader(column string) bool {
    for _, header := range t.headers {
        if header == column {
            return true
        }
    }
    return false
}