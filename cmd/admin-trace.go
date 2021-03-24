/*
 * MinIO Client (C) 2019, 2020, 2021 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"net/http"
	"path"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/mc/pkg/colorjson"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio/pkg/console"
	"github.com/minio/minio/pkg/madmin"
	"github.com/minio/minio/pkg/trace"
)

var adminTraceFlags = []cli.Flag{
	cli.BoolFlag{
		Name:  "verbose, v",
		Usage: "print verbose trace",
	},
	cli.BoolFlag{
		Name:  "all, a",
		Usage: "trace all traffics and POSIX calls",
	},
	cli.StringSliceFlag{
		Name:  "api",
		Usage: "trace only matching API type (values: `s3`, `internal`, `storage`, `os`)",
	},
	cli.StringFlag{
		Name:  "response-threshold",
		Usage: "trace only API which execution duration greater than the threshold (e.g. `5ms`)",
	},

	cli.IntSliceFlag{
		Name:  "status-code",
		Usage: "trace only matching status code",
	},
	cli.StringSliceFlag{
		Name:  "method",
		Usage: "trace only matching HTTP method",
	},
	cli.StringSliceFlag{
		Name:  "funcname",
		Usage: "trace only matching func name",
	},
	cli.StringSliceFlag{
		Name:  "path",
		Usage: "trace only matching path",
	},
	cli.BoolFlag{
		Name:  "errors, e",
		Usage: "trace only failed requests",
	},
}

var adminTraceCmd = cli.Command{
	Name:            "trace",
	Usage:           "show http trace for MinIO server",
	Action:          mainAdminTrace,
	OnUsageError:    onUsageError,
	Before:          setGlobalsFromContext,
	Flags:           append(adminTraceFlags, globalFlags...),
	HideHelpCommand: true,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Show verbose console trace for MinIO server
     {{.Prompt}} {{.HelpName}} -v -a myminio

  2. Show trace only for failed requests for MinIO server
    {{.Prompt}} {{.HelpName}} -v -e myminio

  3. Show verbose console trace for requests with '503' status code
    {{.Prompt}} {{.HelpName}} -v --status-code 503 myminio

  4. Show console trace for a specific path
    {{.Prompt}} {{.HelpName}} --path my-bucket/my-prefix/ myminio

  5. Show console trace for requests with '404' and '503' status code
    {{.Prompt}} {{.HelpName}} --status-code 404 --status-code 503 myminio
`,
}

const timeFormat = "15:04:05.000"

var (
	colors = []color.Attribute{color.FgCyan, color.FgWhite, color.FgYellow, color.FgGreen}
)

func checkAdminTraceSyntax(ctx *cli.Context) {
	if len(ctx.Args()) != 1 {
		cli.ShowCommandHelpAndExit(ctx, "trace", 1) // last argument is exit code
	}
}

func printTrace(verbose bool, traceInfo madmin.ServiceTraceInfo) {
	if verbose {
		printMsg(traceMessage{ServiceTraceInfo: traceInfo})
	} else {
		printMsg(shortTrace(traceInfo))
	}
}

func matchTrace(ctx *cli.Context, traceInfo madmin.ServiceTraceInfo) bool {
	statusCodes := ctx.IntSlice("status-code")
	methods := ctx.StringSlice("method")
	funcNames := ctx.StringSlice("funcname")
	apiPaths := ctx.StringSlice("path")
	if len(statusCodes) == 0 && len(methods) == 0 && len(funcNames) == 0 && len(apiPaths) == 0 {
		// no specific filtering found trace all the requests
		return true
	}

	// Filter request path if passed by the user
	for _, apiPath := range apiPaths {
		if pathMatch(path.Join("/", apiPath), traceInfo.Trace.ReqInfo.Path) {
			return true
		}
	}

	// Filter response status codes if passed by the user
	for _, code := range statusCodes {
		if traceInfo.Trace.RespInfo.StatusCode == code {
			return true
		}
	}

	// Filter request method if passed by the user
	for _, method := range methods {
		if traceInfo.Trace.ReqInfo.Method == method {
			return true
		}
	}

	// Filter request function handler names if passed by the user.
	for _, funcName := range funcNames {
		if nameMatch(funcName, traceInfo.Trace.FuncName) {
			return true
		}
	}

	return false
}

func tracingOpts(ctx *cli.Context) (traceS3, traceInternal, traceStorage, traceOS bool) {
	if ctx.Bool("all") {
		return true, true, true, true
	}

	apis := ctx.StringSlice("api")
	if len(apis) == 0 {
		// If api flag is not specified, then we will
		// trace S3 requests by default.
		return true, false, false, false
	}

	for _, api := range apis {
		switch api {
		case "storage":
			traceStorage = true
		case "internal":
			traceInternal = true
		case "s3":
			traceS3 = true
		case "os":
			traceOS = true
		}
	}

	return
}

// mainAdminTrace - the entry function of trace command
func mainAdminTrace(ctx *cli.Context) error {
	// Check for command syntax
	checkAdminTraceSyntax(ctx)

	verbose := ctx.Bool("verbose")
	errfltr := ctx.Bool("errors")
	aliasedURL := ctx.Args().Get(0)

	var threshold time.Duration
	if t := ctx.String("response-threshold"); t != "" {
		d, e := time.ParseDuration(t)
		fatalIf(probe.NewError(e).Trace(t), "Unable to parse threshold argument.")
		threshold = d
	}

	console.SetColor("Stat", color.New(color.FgYellow))

	console.SetColor("Request", color.New(color.FgCyan))
	console.SetColor("Method", color.New(color.Bold, color.FgWhite))
	console.SetColor("Host", color.New(color.Bold, color.FgGreen))
	console.SetColor("FuncName", color.New(color.Bold, color.FgGreen))

	console.SetColor("ReqHeaderKey", color.New(color.Bold, color.FgWhite))
	console.SetColor("RespHeaderKey", color.New(color.Bold, color.FgCyan))
	console.SetColor("HeaderValue", color.New(color.FgWhite))
	console.SetColor("RespStatus", color.New(color.Bold, color.FgYellow))
	console.SetColor("ErrStatus", color.New(color.Bold, color.FgRed))

	console.SetColor("Response", color.New(color.FgGreen))
	console.SetColor("Body", color.New(color.FgYellow))
	for _, c := range colors {
		console.SetColor(fmt.Sprintf("Node%d", c), color.New(c))
	}
	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	if err != nil {
		fatalIf(err.Trace(aliasedURL), "Unable to initialize admin client.")
		return nil
	}

	ctxt, cancel := context.WithCancel(globalContext)
	defer cancel()

	traceS3, traceInternal, traceStorage, traceOS := tracingOpts(ctx)

	opts := madmin.ServiceTraceOpts{
		Internal:   traceInternal,
		Storage:    traceStorage,
		OS:         traceOS,
		S3:         traceS3,
		OnlyErrors: errfltr,
		Threshold:  threshold,
	}

	// Start listening on all trace activity.
	traceCh := client.ServiceTrace(ctxt, opts)
	for traceInfo := range traceCh {
		if traceInfo.Err != nil {
			fatalIf(probe.NewError(traceInfo.Err), "Unable to listen to http trace")
		}
		if matchTrace(ctx, traceInfo) {
			printTrace(verbose, traceInfo)
		}
	}
	return nil
}

// Short trace record
type shortTraceMsg struct {
	Status     string    `json:"status"`
	Host       string    `json:"host"`
	Time       time.Time `json:"time"`
	Client     string    `json:"client"`
	CallStats  callStats `json:"callStats"`
	FuncName   string    `json:"api"`
	Path       string    `json:"path"`
	Query      string    `json:"query"`
	StatusCode int       `json:"statusCode"`
	StatusMsg  string    `json:"statusMsg"`

	StorageStats storageStats `json:"storageStats"`
	OSStats      osStats      `json:"osStats"`
	Type         trace.Type   `json:"type"`
}

type traceMessage struct {
	Status string `json:"status"`
	madmin.ServiceTraceInfo
}

type requestInfo struct {
	Time     time.Time         `json:"time"`
	Proto    string            `json:"proto"`
	Method   string            `json:"method"`
	Path     string            `json:"path,omitempty"`
	RawQuery string            `json:"rawQuery,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
}

type responseInfo struct {
	Time       time.Time         `json:"time"`
	Headers    map[string]string `json:"headers,omitempty"`
	Body       string            `json:"body,omitempty"`
	StatusCode int               `json:"statusCode,omitempty"`
}

type callStats struct {
	Rx       int           `json:"rx"`
	Tx       int           `json:"tx"`
	Duration time.Duration `json:"duration"`
	Ttfb     time.Duration `json:"timeToFirstByte"`
}

type osStats struct {
	Duration time.Duration `json:"duration"`
	Path     string        `json:"path"`
}

type storageStats struct {
	Duration time.Duration `json:"duration"`
	Path     string        `json:"path"`
}

type verboseTrace struct {
	Type trace.Type `json:"type"`

	NodeName string    `json:"host"`
	FuncName string    `json:"api"`
	Time     time.Time `json:"time"`

	RequestInfo  requestInfo  `json:"request"`
	ResponseInfo responseInfo `json:"response"`
	CallStats    callStats    `json:"callStats"`

	StorageStats storageStats `json:"storageStats"`
	OSStats      osStats      `json:"osStats"`
}

// return a struct with minimal trace info.
func shortTrace(ti madmin.ServiceTraceInfo) shortTraceMsg {
	s := shortTraceMsg{}
	t := ti.Trace

	s.Type = t.TraceType
	s.FuncName = t.FuncName
	s.Time = t.Time

	switch t.TraceType {
	case trace.Storage:
		s.Path = t.StorageStats.Path
		s.StorageStats.Duration = t.StorageStats.Duration
	case trace.OS:
		s.Path = t.OSStats.Path
		s.OSStats.Duration = t.OSStats.Duration
	case trace.HTTP:
		if host, ok := t.ReqInfo.Headers["Host"]; ok {
			s.Host = strings.Join(host, "")
		}
		s.Path = t.ReqInfo.Path
		s.Query = t.ReqInfo.RawQuery
		s.StatusCode = t.RespInfo.StatusCode
		s.StatusMsg = http.StatusText(t.RespInfo.StatusCode)
		s.Client = t.ReqInfo.Client
		s.CallStats.Duration = t.CallStats.Latency
		s.CallStats.Rx = t.CallStats.InputBytes
		s.CallStats.Tx = t.CallStats.OutputBytes
	}
	return s
}

func (s shortTraceMsg) JSON() string {
	s.Status = "success"
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", " ")
	// Disable escaping special chars to display XML tags correctly
	enc.SetEscapeHTML(false)

	fatalIf(probe.NewError(enc.Encode(s)), "Unable to marshal into JSON.")
	return buf.String()
}

func (s shortTraceMsg) String() string {
	var hostStr string
	var b = &strings.Builder{}

	switch s.Type {
	case trace.Storage:
		fmt.Fprintf(b, "[%s] %s %s %2s", console.Colorize("RespStatus", "STORAGE"), console.Colorize("FuncName", s.FuncName),
			s.Path,
			console.Colorize("HeaderValue", s.StorageStats.Duration))
		return b.String()
	case trace.OS:
		fmt.Fprintf(b, "[%s] %s %s %2s", console.Colorize("RespStatus", "OS"), console.Colorize("FuncName", s.FuncName),
			s.Path,
			console.Colorize("HeaderValue", s.OSStats.Duration))
		return b.String()
	}

	// HTTP trace

	if s.Host != "" {
		hostStr = colorizedNodeName(s.Host)
	}
	fmt.Fprintf(b, "%s ", s.Time.Format(timeFormat))

	statusStr := fmt.Sprintf("%d %s", s.StatusCode, s.StatusMsg)
	if s.StatusCode >= http.StatusBadRequest {
		statusStr = console.Colorize("ErrStatus", statusStr)
	} else {
		statusStr = console.Colorize("RespStatus", statusStr)
	}

	fmt.Fprintf(b, "[%s] %s ", statusStr, console.Colorize("FuncName", s.FuncName))
	fmt.Fprintf(b, "%s%s", hostStr, s.Path)

	if s.Query != "" {
		fmt.Fprintf(b, "?%s ", s.Query)
	}
	fmt.Fprintf(b, " %s ", s.Client)

	spaces := 15 - len(s.Client)
	fmt.Fprintf(b, "%*s", spaces, " ")
	fmt.Fprint(b, console.Colorize("HeaderValue", fmt.Sprintf("  %2s", s.CallStats.Duration.Round(time.Microsecond))))
	spaces = 12 - len(fmt.Sprintf("%2s", s.CallStats.Duration.Round(time.Microsecond)))
	fmt.Fprintf(b, "%*s", spaces, " ")
	fmt.Fprint(b, console.Colorize("Stat", " ↑ "))
	fmt.Fprint(b, console.Colorize("HeaderValue", humanize.IBytes(uint64(s.CallStats.Rx))))
	fmt.Fprint(b, console.Colorize("Stat", " ↓ "))
	fmt.Fprint(b, console.Colorize("HeaderValue", humanize.IBytes(uint64(s.CallStats.Tx))))

	return b.String()
}

// colorize node name
func colorizedNodeName(nodeName string) string {
	nodeHash := fnv.New32a()
	nodeHash.Write([]byte(nodeName))
	nHashSum := nodeHash.Sum32()
	idx := uint32(nHashSum) % uint32(len(colors))
	return console.Colorize(fmt.Sprintf("Node%d", colors[idx]), nodeName)
}

func (t traceMessage) JSON() string {
	t.Status = "success"
	rqHdrs := make(map[string]string)
	rspHdrs := make(map[string]string)
	rq := t.Trace.ReqInfo
	rs := t.Trace.RespInfo
	for k, v := range rq.Headers {
		rqHdrs[k] = strings.Join(v, " ")
	}
	for k, v := range rs.Headers {
		rspHdrs[k] = strings.Join(v, " ")
	}
	trc := verboseTrace{
		Type:     t.Trace.TraceType,
		NodeName: t.Trace.NodeName,
		FuncName: t.Trace.FuncName,
		Time:     t.Trace.Time,
		RequestInfo: requestInfo{
			Time:     rq.Time,
			Proto:    rq.Proto,
			Method:   rq.Method,
			Path:     rq.Path,
			RawQuery: rq.RawQuery,
			Body:     string(rq.Body),
			Headers:  rqHdrs,
		},
		ResponseInfo: responseInfo{
			Time:       rs.Time,
			Body:       string(rs.Body),
			Headers:    rspHdrs,
			StatusCode: rs.StatusCode,
		},
		CallStats: callStats{
			Duration: t.Trace.CallStats.Latency,
			Rx:       t.Trace.CallStats.InputBytes,
			Tx:       t.Trace.CallStats.OutputBytes,
			Ttfb:     t.Trace.CallStats.TimeToFirstByte,
		},
		OSStats: osStats{
			Duration: t.Trace.OSStats.Duration,
			Path:     t.Trace.OSStats.Path,
		},
		StorageStats: storageStats{
			Duration: t.Trace.StorageStats.Duration,
			Path:     t.Trace.StorageStats.Path,
		},
	}
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetIndent("", " ")
	// Disable escaping special chars to display XML tags correctly
	enc.SetEscapeHTML(false)
	fatalIf(probe.NewError(enc.Encode(trc)), "Unable to marshal into JSON.")

	// strip off extra newline added by json encoder
	return strings.TrimSuffix(buf.String(), "\n")
}

func (t traceMessage) String() string {
	var nodeNameStr string
	var b = &strings.Builder{}

	trc := t.Trace
	if trc.NodeName != "" {
		nodeNameStr = fmt.Sprintf("%s ", colorizedNodeName(trc.NodeName))
	}

	switch trc.TraceType {
	case trace.Storage:
		fmt.Fprintf(b, "%s %s [%s] %s %s", nodeNameStr, console.Colorize("Request", fmt.Sprintf("[STORAGE %s]", trc.FuncName)), trc.Time.Format(timeFormat), trc.StorageStats.Path, trc.StorageStats.Duration)
		return b.String()
	case trace.OS:
		fmt.Fprintf(b, "%s %s [%s] %s %s", nodeNameStr, console.Colorize("Request", fmt.Sprintf("[POSIX %s]", trc.FuncName)), trc.Time.Format(timeFormat), trc.OSStats.Path, trc.OSStats.Duration)
		return b.String()
	}

	ri := trc.ReqInfo
	rs := trc.RespInfo
	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Request", fmt.Sprintf("[REQUEST %s] ", trc.FuncName)))
	fmt.Fprintf(b, "[%s] %s\n", ri.Time.Format(timeFormat), console.Colorize("Host", fmt.Sprintf("[Client IP: %s]", ri.Client)))
	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Method", fmt.Sprintf("%s %s", ri.Method, ri.Path)))
	if ri.RawQuery != "" {
		fmt.Fprintf(b, "?%s", ri.RawQuery)
	}
	fmt.Fprint(b, "\n")
	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Method", fmt.Sprintf("Proto: %s\n", ri.Proto)))
	host, ok := ri.Headers["Host"]
	if ok {
		delete(ri.Headers, "Host")
	}
	hostStr := strings.Join(host, "")
	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Host", fmt.Sprintf("Host: %s\n", hostStr)))
	for k, v := range ri.Headers {
		fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("ReqHeaderKey",
			fmt.Sprintf("%s: ", k))+console.Colorize("HeaderValue", fmt.Sprintf("%s\n", strings.Join(v, ""))))
	}

	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Body", fmt.Sprintf("%s\n", string(ri.Body))))
	fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("Response", "[RESPONSE] "))
	fmt.Fprintf(b, "[%s] ", rs.Time.Format(timeFormat))
	fmt.Fprint(b, console.Colorize("Stat", fmt.Sprintf("[ Duration %2s  ↑ %s  ↓ %s ]\n", trc.CallStats.Latency.Round(time.Microsecond), humanize.IBytes(uint64(trc.CallStats.InputBytes)), humanize.IBytes(uint64(trc.CallStats.OutputBytes)))))

	statusStr := console.Colorize("RespStatus", fmt.Sprintf("%d %s", rs.StatusCode, http.StatusText(rs.StatusCode)))
	if rs.StatusCode != http.StatusOK {
		statusStr = console.Colorize("ErrStatus", fmt.Sprintf("%d %s", rs.StatusCode, http.StatusText(rs.StatusCode)))
	}
	fmt.Fprintf(b, "%s%s\n", nodeNameStr, statusStr)

	for k, v := range rs.Headers {
		fmt.Fprintf(b, "%s%s", nodeNameStr, console.Colorize("RespHeaderKey",
			fmt.Sprintf("%s: ", k))+console.Colorize("HeaderValue", fmt.Sprintf("%s\n", strings.Join(v, ""))))
	}
	fmt.Fprintf(b, "%s%s\n", nodeNameStr, console.Colorize("Body", string(rs.Body)))
	fmt.Fprint(b, nodeNameStr)
	return b.String()
}
