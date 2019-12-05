/*
 * MinIO Client (C) 2019 MinIO, Inc.
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
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/dustin/go-humanize/english"
	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/mc/pkg/colorjson"
	"github.com/minio/mc/pkg/console"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio/pkg/madmin"
)

var adminInfoCmd = cli.Command{
	Name:   "info",
	Usage:  "display MinIO server information",
	Action: mainAdminInfo,
	Before: setGlobalsFromContext,
	Flags:  globalFlags,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Get server information of the 'play' MinIO server.
     {{.Prompt}} {{.HelpName}} play/
`,
}

// Wrap "Info" message together with fields "Status" and "Error"
type clusterStruct struct {
	Status string             `json:"status"`
	Error  string             `json:"error,omitempty"`
	Info   madmin.InfoMessage `json:"info,omitempty"`
}

// String provides colorized info messages.
func (u clusterStruct) String() (msg string) {
	// If nothing has been collected, error out
	if u.Info.Servers == nil {
		fatal(probe.NewError(errors.New("Cannot get service status")), "")
	}
	// Initialization
	var totalOnlineDisksCluster int
	var totalOfflineDisksCluster int
	// Dot represents server status, online (green) or offline (red)
	dot := "●"
	// Color palette initialization
	console.SetColor("Info", color.New(color.FgGreen, color.Bold))
	console.SetColor("InfoFail", color.New(color.FgRed, color.Bold))
	// MinIO server type default
	backendType := "Unknown"

	// Loop through each server and put together info for each one
	for _, srv := range u.Info.Servers {
		// Check if MinIO server is offline ("Mode" field),
		// If offline, error out
		if u.Info.Mode == "offline" {
			// "PrintB" is color blue in console library package
			msg += fmt.Sprintf("%s  %s\n", console.Colorize("InfoFail", dot), console.Colorize("PrintB", srv.Endpoint))
			msg += fmt.Sprintf("   Uptime: %s\n", console.Colorize("InfoFail", "offline"))
			return
		}

		// Check cluster level "Status" field for error
		if u.Status == "error" {
			fatal(probe.NewError(errors.New(u.Error)), "Cannot get service status")
		}

		// Set the type of MinIO server ("FS", "Erasure", "Unknown")
		v := reflect.ValueOf(u.Info.Backend)
		if v.Kind() == reflect.Map {
			for _, key := range v.MapKeys() {
				val := v.MapIndex(key)
				switch t := val.Interface().(type) {
				case string:
					backendType = t
				}
			}
		}
		// Print server title
		msg += fmt.Sprintf("%s  %s\n", console.Colorize("Info", dot), console.Colorize("PrintB", srv.Endpoint))

		// Uptime
		msg += fmt.Sprintf("   Uptime: %s\n", console.Colorize("Info",
			humanize.RelTime(time.Now(), time.Now().Add(time.Duration(srv.Uptime)*time.Second), "", "")))

		// Version
		version := srv.Version
		if srv.Version == "DEVELOPMENT.GOGET" {
			version = "<development>"
		}
		msg += fmt.Sprintf("   Version: %s\n", version)

		// Network info, only available for non-FS types
		var connectionAlive int
		totalNodes := strconv.Itoa(len(srv.Network))
		if srv.Network != nil {
			for _, v := range srv.Network {
				if v == "online" {
					connectionAlive++
				}
			}
			displayNwInfo := strconv.Itoa(connectionAlive) + "/" + totalNodes
			msg += fmt.Sprintf("   Network: %s %s\n", displayNwInfo, console.Colorize("Info", "OK "))
		}

		// Choose and display information depending on the type of a server
		//        FS server                          non-FS server
		// ==============================  ===================================
		// ● <ip>:<port>                   ● <ip>:<port>
		//   Uptime: xxx                     Uptime: xxx
		//   Version: xxx                    Version: xxx
		//   Network: X/Y OK                 Network: X/Y OK
		//
		// U Used, B Buckets, O Objects    Drives: N/N OK
		//
		//                                   U Used, B Buckets, O Objects
		//                                   N drives online, K drives offline
		//
		if backendType != "FS" {
			// Info about drives on a server, only available for non-FS types
			var OffDisks int
			var OnDisks int
			var dispNoOfDisks string
			for _, disk := range srv.Disks {
				if disk.State == "ok" {
					OnDisks++
				} else {
					OffDisks++
				}
			}

			totalDisksPerServer := OnDisks + OffDisks
			totalOnlineDisksCluster += OnDisks
			totalOfflineDisksCluster += OffDisks

			dispNoOfDisks = strconv.Itoa(OnDisks) + "/" + strconv.Itoa(totalDisksPerServer)
			msg += fmt.Sprintf("   Drives: %s %s\n", dispNoOfDisks, console.Colorize("Info", "OK "))

		}
		msg += "\n"
	}

	// Summary on used space, total no of buckets and
	// total no of objects at the Cluster level
	usedTotal := humanize.IBytes(uint64(u.Info.Usage.Size))
	msg += fmt.Sprintf("%s Used, %s, %s", usedTotal,
		english.Plural(u.Info.Buckets.Count, "Bucket", ""),
		english.Plural(u.Info.Objects.Count, "Object", ""))

	if backendType != "FS" {
		// Summary on total no of online and total
		// number of offline disks at the Cluster level
		msg += fmt.Sprintf("\n%s online, %s offline",
			english.Plural(totalOnlineDisksCluster, "drive", ""),
			english.Plural(totalOfflineDisksCluster, "drive", ""))
	}

	return
}

// JSON jsonifies service status message.
func (u clusterStruct) JSON() string {
	statusJSONBytes, e := json.MarshalIndent(u, "", "    ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(statusJSONBytes)
}

// checkAdminInfoSyntax - validate arguments passed by a user
func checkAdminInfoSyntax(ctx *cli.Context) {
	if len(ctx.Args()) == 0 || len(ctx.Args()) > 1 {
		cli.ShowCommandHelpAndExit(ctx, "info", 1) // last argument is exit code
	}
}

func mainAdminInfo(ctx *cli.Context) error {
	checkAdminInfoSyntax(ctx)

	// Get the alias parameter from cli
	args := ctx.Args()
	aliasedURL := args.Get(0)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	var clusterInfo clusterStruct
	// Fetch info of all servers (cluster or single server)
	admInfo, e := client.ServerInfo()
	if e != nil {
		clusterInfo.Status = "error"
		clusterInfo.Error = e.Error()
	} else {
		clusterInfo.Status = "success"
		clusterInfo.Error = ""
	}
	clusterInfo.Info = admInfo
	printMsg(clusterStruct(clusterInfo))

	return nil
}
