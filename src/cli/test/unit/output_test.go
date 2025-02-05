package output_test

import (
    "bytes"
    "encoding/json"
    "os"
    "sync"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "golang.org/x/term"

    "github.com/blackpoint/cli/internal/output/formatter"
    "github.com/blackpoint/cli/internal/output/printer"
    "github.com/blackpoint/cli/internal/output/table"
)

// Test fixtures
var testData = map[string]interface{}{
    "string": "test",
    "number": 42,
    "nested": map[string]interface{}{
        "array": []string{"a", "b", "c"},
        "object": map[string]interface{}{
            "key": "value",
        },
    },
}

var testTableData = [][]string{
    {"ID", "Status", "Description"},
    {"1", "Success ✓", "Operation completed"},
    {"2", "Error ✗", "Connection failed"},
    {"3", "Warning ⚠", "Resource not found"},
}

// Mock terminal for testing
type mockTerminal struct {
    width  int
    height int
    isTerm bool
}

func TestFormatJSON(t *testing.T) {
    t.Run("formats valid data structure", func(t *testing.T) {
        formatted, err := formatter.FormatJSON(testData, &formatter.JSONOptions{
            Indent:     "  ",
            EscapeHTML: true,
            SortKeys:   true,
        })
        
        require.NoError(t, err)
        assert.Contains(t, formatted, "\"string\": \"test\"")
        assert.Contains(t, formatted, "\"number\": 42")
        
        // Verify valid JSON
        var parsed map[string]interface{}
        err = json.Unmarshal([]byte(formatted), &parsed)
        assert.NoError(t, err)
    })

    t.Run("handles nil input", func(t *testing.T) {
        _, err := formatter.FormatJSON(nil, nil)
        assert.Error(t, err)
        assert.Contains(t, err.Error(), "nil data provided")
    })

    t.Run("handles concurrent formatting", func(t *testing.T) {
        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                _, err := formatter.FormatJSON(testData, nil)
                assert.NoError(t, err)
            }()
        }
        wg.Wait()
    })
}

func TestFormatTable(t *testing.T) {
    t.Run("formats table with borders", func(t *testing.T) {
        opts := table.TableOptions{
            Border:      true,
            CenterAlign: false,
            AutoWrap:    true,
            MinWidth:    10,
        }

        tbl, err := table.NewTable(testTableData[0], opts)
        require.NoError(t, err)

        err = tbl.AddRows(testTableData[1:])
        require.NoError(t, err)

        output, err := tbl.Render()
        require.NoError(t, err)

        // Verify table structure
        assert.Contains(t, output, "ID")
        assert.Contains(t, output, "Status")
        assert.Contains(t, output, "Description")
        assert.Contains(t, output, "+") // Border character
        assert.Contains(t, output, "|") // Column separator
    })

    t.Run("handles unicode characters", func(t *testing.T) {
        opts := table.TableOptions{
            Border:      true,
            AutoWrap:    true,
            MinWidth:    10,
        }

        unicodeData := [][]string{
            {"Name", "Symbol"},
            {"Check", "✓"},
            {"Cross", "✗"},
            {"Warning", "⚠"},
        }

        tbl, err := table.NewTable(unicodeData[0], opts)
        require.NoError(t, err)

        err = tbl.AddRows(unicodeData[1:])
        require.NoError(t, err)

        output, err := tbl.Render()
        require.NoError(t, err)

        assert.Contains(t, output, "✓")
        assert.Contains(t, output, "✗")
        assert.Contains(t, output, "⚠")
    })
}

func TestPrinter(t *testing.T) {
    t.Run("prints success message", func(t *testing.T) {
        var buf bytes.Buffer
        p, err := printer.NewPrinter(&buf, true, false)
        require.NoError(t, err)

        err = p.PrintSuccess("Operation completed")
        require.NoError(t, err)

        output := buf.String()
        assert.Contains(t, output, "Operation completed")
        assert.Contains(t, output, "✓") // Success checkmark
    })

    t.Run("prints error message", func(t *testing.T) {
        var buf bytes.Buffer
        p, err := printer.NewPrinter(&buf, true, false)
        require.NoError(t, err)

        testErr := fmt.Errorf("test error")
        err = p.PrintError("Operation failed", testErr)
        require.NoError(t, err)

        output := buf.String()
        assert.Contains(t, output, "Operation failed")
        assert.Contains(t, output, "test error")
        assert.Contains(t, output, "✗") // Error cross
    })

    t.Run("handles concurrent printing", func(t *testing.T) {
        var buf bytes.Buffer
        p, err := printer.NewPrinter(&buf, true, false)
        require.NoError(t, err)

        var wg sync.WaitGroup
        for i := 0; i < 10; i++ {
            wg.Add(1)
            go func(i int) {
                defer wg.Done()
                msg := fmt.Sprintf("Message %d", i)
                err := p.PrintSuccess(msg)
                assert.NoError(t, err)
            }(i)
        }
        wg.Wait()

        output := buf.String()
        for i := 0; i < 10; i++ {
            assert.Contains(t, output, fmt.Sprintf("Message %d", i))
        }
    })
}

func TestProgressBar(t *testing.T) {
    t.Run("displays progress updates", func(t *testing.T) {
        var buf bytes.Buffer
        p, err := printer.NewPrinter(&buf, true, false)
        require.NoError(t, err)

        total := int64(100)
        bar, err := p.PrintProgress(total, "Processing", formatter.ProgressOptions{
            Width:          50,
            ShowPercentage: true,
            ShowSpeed:      true,
            ShowRemaining:  true,
        })
        require.NoError(t, err)

        // Simulate progress updates
        for i := int64(0); i <= total; i += 10 {
            err := bar.Set(i)
            assert.NoError(t, err)
            time.Sleep(10 * time.Millisecond)
        }

        output := buf.String()
        assert.Contains(t, output, "Processing")
        assert.Contains(t, output, "%")
    })

    t.Run("handles terminal resize", func(t *testing.T) {
        if !term.IsTerminal(int(os.Stdout.Fd())) {
            t.Skip("Test requires terminal")
        }

        p, err := printer.NewPrinter(os.Stdout, true, false)
        require.NoError(t, err)

        bar, err := p.PrintProgress(100, "Processing", formatter.ProgressOptions{
            Width:          50,
            ShowPercentage: true,
        })
        require.NoError(t, err)

        // Trigger resize event
        p.HandleResize(80)

        err = bar.Set(50)
        assert.NoError(t, err)
    })
}