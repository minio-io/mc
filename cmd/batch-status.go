package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/dustin/go-humanize"
	"github.com/minio/cli"
	"github.com/minio/madmin-go"
	"github.com/minio/mc/pkg/probe"
	"github.com/olekukonko/tablewriter"
)

var batchStatusCmd = cli.Command{
	Name:            "status",
	Usage:           "summarize job events on MinIO server in real-time",
	Action:          mainBatchStatus,
	OnUsageError:    onUsageError,
	Before:          setGlobalsFromContext,
	Flags:           globalFlags,
	HideHelpCommand: true,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} TARGET JOBID

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
   1. Display current in-progress JOB events.
      {{.Prompt}} {{.HelpName}} myminio/ KwSysDpxcBU9FNhGkn2dCf
`,
}

// checkBatchStatusSyntax - validate all the passed arguments
func checkBatchStatusSyntax(ctx *cli.Context) {
	if len(ctx.Args()) != 2 {
		showCommandHelpAndExit(ctx, ctx.Command.Name, 1) // last argument is exit code
	}
}

func mainBatchStatus(ctx *cli.Context) error {
	checkBatchStatusSyntax(ctx)

	aliasedURL := ctx.Args().Get(0)
	jobID := ctx.Args().Get(1)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err.Trace(aliasedURL), "Unable to initialize admin client.")

	ctxt, cancel := context.WithCancel(globalContext)
	defer cancel()

	done := make(chan struct{})

	_, e := client.DescribeBatchJob(ctxt, jobID)
	fatalIf(probe.NewError(e), "Unable to lookup job status")

	ui := tea.NewProgram(initBatchJobMetricsUI(jobID))
	if !globalJSON {
		go func() {
			if e := ui.Start(); e != nil {
				cancel()
				os.Exit(1)
			}
			close(done)
		}()
	}

	go func() {
		opts := madmin.MetricsOptions{
			Type:    madmin.MetricsBatchJobs,
			ByJobID: jobID,
		}
		e := client.Metrics(ctxt, opts, func(metrics madmin.RealtimeMetrics) {
			if globalJSON {
				printMsg(metricsMessage{RealtimeMetrics: metrics})
				return
			}
			if metrics.Aggregated.BatchJobs != nil {
				job := metrics.Aggregated.BatchJobs.Jobs[jobID]
				ui.Send(job)
				if job.Complete {
					cancel()
				}
			}
		})
		if e != nil && !errors.Is(e, context.Canceled) {
			fatalIf(probe.NewError(e).Trace(ctx.Args()...), "Unable to get current status")
		}
	}()

	<-done
	return nil
}

func initBatchJobMetricsUI(jobID string) *batchJobMetricsUI {
	s := spinner.New()
	s.Spinner = spinner.Points
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))
	return &batchJobMetricsUI{
		spinner: s,
		jobID:   jobID,
	}
}

type batchJobMetricsUI struct {
	current  madmin.JobMetric
	spinner  spinner.Model
	quitting bool
	jobID    string
}

func (m *batchJobMetricsUI) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m *batchJobMetricsUI) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		default:
			return m, nil
		}
	case madmin.JobMetric:
		m.current = msg
		if msg.Complete {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil
	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd
	default:
		return m, nil
	}
}

func (m *batchJobMetricsUI) View() string {
	var s strings.Builder

	// Set table header
	table := tablewriter.NewWriter(&s)
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetBorder(false)
	table.SetTablePadding("\t") // pad with tabs
	table.SetNoWhiteSpace(true)

	var data [][]string
	addLine := func(prefix string, value interface{}) {
		data = append(data, []string{
			prefix,
			whiteStyle.Render(fmt.Sprint(value)),
		})
	}

	if !m.quitting {
		s.WriteString(m.spinner.View())
	} else {
		if m.current.Complete {
			if m.current.Replicate.ObjectsFailed == 0 {
				s.WriteString(m.spinner.Style.Render((tickCell + tickCell + tickCell)))
			} else {
				s.WriteString(m.spinner.Style.Render((crossTickCell + crossTickCell + crossTickCell)))
			}
		}
	}
	s.WriteString("\n")

	switch m.current.JobType {
	case string(madmin.BatchJobReplicate):
		accElapsedTime := m.current.LastUpdate.Sub(m.current.StartTime)

		addLine("JobType: ", m.current.JobType)
		addLine("Objects: ", m.current.Replicate.Objects)
		addLine("Versions: ", m.current.Replicate.Objects)
		addLine("FailedObjects: ", m.current.Replicate.ObjectsFailed)
		if accElapsedTime > 0 {
			bytesTransferredPerSec := float64(int64(time.Second)*m.current.Replicate.BytesTransferred) / float64(accElapsedTime)
			objectsPerSec := float64(int64(time.Second)*m.current.Replicate.Objects) / float64(accElapsedTime)
			addLine("Throughput: ", fmt.Sprintf("%s/s", humanize.IBytes(uint64(bytesTransferredPerSec))))
			addLine("IOPs: ", fmt.Sprintf("%.2f objs/s", objectsPerSec))
		}
		addLine("Transferred: ", fmt.Sprintf("%s", humanize.IBytes(uint64(m.current.Replicate.BytesTransferred))))
		addLine("Elapsed: ", fmt.Sprintf("%s", accElapsedTime))
		addLine("CurrObjName: ", m.current.Replicate.Object)
	}

	table.AppendBulk(data)
	table.Render()

	if m.quitting {
		s.WriteString("\n")
	}
	return s.String()
}