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
	"fmt"
	"net/url"

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

// // backendType - indicates the type of backend storage
// type backendType string

// const (
// 	fsType      = backendType("FS")
// 	erasureType = backendType("Erasure")
// )

// // fsBackend contains specific FS storage information
// type fsBackend struct {
// 	Type backendType `json:"type"`
// }

// // xlBackend contains specific erasure storage information
// type xlBackend struct {
// 	Type             backendType         `json:"type"`
// 	OnlineDisks      madmin.BackendDisks `json:"onlineDisks"`      // Online disks during server startup.
// 	OfflineDisks     madmin.BackendDisks `json:"offlineDisks"`     // Offline disks during server startup.
// 	StandardSCData   int                 `json:"standarSCData"`    // Data disks for currently configured Standard storage class.
// 	StandardSCParity int                 `json:"standardSCParity"` // Parity disks for currently configured Standard storage class.
// 	RRSCData         int                 `json:"rrSCData"`         // Data disks for currently configured Reduced Redundancy storage class.
// 	RRSCParity       int                 `json:"rrSCParity"`       // Parity disks for currently configured Reduced Redundancy storage class.
// }

// // Vault - Fetches the Vault status
// // type Vault struct {
// // 	Status  madmin.Status `json:"status"`
// // 	Encrypt string `json:"encrypt"`
// // 	Decrypt string `json:"decrypt"`
// // 	Update  string `json:"update"`
// // }
// var Vault madmin.Vault

// // Ldap contains status
// type Ldap struct {
// 	Status string `json:"status"`
// }

// // Logger contains logger status
// type Logger struct {
// 	Status string `json:"status"`
// }

// // Audit contains audit logger status
// type Audit struct {
// 	Status string `json:"status"`
// }

// // Notifications contains notification target info
// type Notifications struct {
// 	AMQP []Status `json:"amqp"`
// }

// // WebhookTarget Contains  Webhook info
// type WebhookTarget struct {
// 	Status string `json:"status"`
// }

// type diskStruct struct {
// 	Path            string `json:"path"`
// 	State           string `json:"state"`
// 	UUID            string `json:"uuid"`
// 	Model           string `json:"model"`
// 	Totalspace      string `json:"totalspace"`
// 	Usedspace       string `json:"usedspace"`
// 	Readthroughput  string `json:"readthroughput"`
// 	Writethroughput string `json:"writethroughput"`
// 	Readlatency     string `json:"readlatency"`
// 	Writelatency    string `json:"writelatency"`
// 	Utilization     string `json:"utilization"`
// }

// type serverStruct struct {
// 	State    string                 `json:"state"`
// 	Endpoint string                 `json:"endpoint"`
// 	Uptime   time.Duration          `json:"uptime"`
// 	Version  string                 `json:"version"`
// 	CommitID string                 `json:"commitID"`
// 	Network  madmin.ServerConnStats `json:"network"`
// 	Disks    []diskStruct           `json:"disks"`
// }

// var storageInfoStat interface{}

// // infoMessage container to hold service status information.
// type infoMessage struct {
// 	Mode         string   `json:"Mode"`
// 	Domain       []string `json:"domain"`
// 	Region       string   `json:"region"`
// 	SQSARN       []string `json:"sqsARN"`
// 	DeploymentID string   `json:"deploymentID"`
// 	Buckets      struct {
// 		Count int `json: "count"`
// 	} `json:"buckets"`
// 	Objects struct {
// 		Count int `json:"count`
// 	} `json:"objects"`
// 	Usage struct {
// 		Size int64 `json:"size"`
// 	} `json:"usage"`
// 	Services struct {
// 		Vault         Vault         `json:"vault"`
// 		Ldap          Ldap          `json:"ldap"`
// 		Logger        []Logger      `json:"logger"`
// 		Audit         []Audit       `json:"audit"`
// 		Notifications Notifications `json:"notifications"`
// 	} `json:"services"`
// 	// // Construct the backend status
// 	// if storageInfo.Backend.Type == madmin.Erasure {
// 	// 	storageInfoStat = xlBackend{
// 	// 		Type:         erasureType,
// 	// 		OnlineDisks:  filterPerNode(serverInfo.Addr, storageInfo.Backend.OnlineDisks),
// 	// 		OfflineDisks: filterPerNode(serverInfo.Addr, storageInfo.Backend.OfflineDisks),
// 	// 		Sets:         storageInfo.Backend.Sets,
// 	// 	}
// 	// } else {
// 	// 	storageInfoStat = fsBackend{
// 	// 		Type: fsType,
// 	// 	}
// 	// }
// 	Servers []serverStruct
// }

// func filterPerNode(addr string, m map[string]int) int {
// 	if val, ok := m[addr]; ok {
// 		return val
// 	}
// 	return -1
// }

// InfoMessage container to hold server admin related information.
type infoMessage struct {
	Mode         string   `json:"mode"`
	Domain       []string `json:"domain"`
	Region       string   `json:"region"`
	SQSARN       []string `json:"sqsARN"`
	DeploymentID string   `json:"deploymentID"`
	Buckets      struct {
		Count int `json:"count"`
	} `json:"buckets"`
	Objects struct {
		Count int `json:"count"`
	} `json:"objects"`
	Usage struct {
		Size int `json:"size"`
	} `json:"usage"`
	Services struct {
		Vault         madmin.Vault         `json:"vault"`
		Ldap          madmin.Ldap          `json:"ldap"`
		Logger        []madmin.Logger      `json:"logger"`
		Audit         []madmin.Audit       `json:"audit"`
		Notifications madmin.Notifications `json:"notifications"`
	} `json:"services"`
	Backend madmin.BackendInfo `json:"backend"`
}

// String colorized service status message.
func (u infoMessage) String() (msg string) {
	msg += "\n"
	dot := "●"

	// When MinIO server is offline ("Mode" field)
	if u.Mode == "offline" {
		msg += fmt.Sprintf("%s  %s\n", console.Colorize("InfoFail", dot), console.Colorize("PrintB", u.Domain))
		msg += fmt.Sprintf("Uptime: %s\n", console.Colorize("InfoFail", "offline"))
		return
	}

	// // Print error if any and exit
	// if u.Err != "" {
	// 	msg += fmt.Sprintf("%s  %s\n", console.Colorize("InfoFail", dot), console.Colorize("PrintB", u.Addr))
	// 	msg += fmt.Sprintf("Uptime: %s\n", console.Colorize("InfoFail", "offline"))
	// 	e := u.Err
	// 	if strings.Trim(e, " ") == "rpc: retry error" {
	// 		e = "unreachable"
	// 	}
	// 	msg += fmt.Sprintf("Error: %s", console.Colorize("InfoFail", e))
	// 	return
	// }

	// Print server title
	msg += fmt.Sprintf("%s  %s\n", console.Colorize("Info", dot), console.Colorize("PrintB", u.Domain))

	// Uptime (this is per server)
	// msg += fmt.Sprintf("Uptime: %s\n", console.Colorize("Info",
	// 	humanize.RelTime(time.Now(), time.Now().Add(-u.ServersInfo[0].Uptime), "", "")))

	// // Version (this is per server)
	// version := u.ServersInfo[0].Version
	// if u.ServersInfo[0].Version == "DEVELOPMENT.GOGET" {
	// 	version = "<development>"
	// }
	// msg += fmt.Sprintf("Version: %s\n", version)

	// Region
	if u.Region != "" {
		msg += fmt.Sprintf("Region: %s\n", u.Region)
	}

	// ARNs
	sqsARNs := ""
	for _, v := range u.SQSARN {
		sqsARNs += fmt.Sprintf("%s ", v)
	}
	if sqsARNs != "" {
		msg += fmt.Sprintf("SQS ARNs: %s\n", sqsARNs)
	}

	// // Incoming/outgoing
	// if v, ok := u.StorageInfo.(xlBackend); ok {
	// 	upBackends := 0
	// 	downBackends := 0
	// 	for _, set := range v.Sets {
	// 		for i, s := range set {
	// 			if len(s.Endpoint) > 0 && (strings.Contains(s.Endpoint, u.Addr) || s.Endpoint[i] == '/' || s.Endpoint[i] == '.') {
	// 				if s.State == "ok" {
	// 					upBackends++
	// 				} else {
	// 					downBackends++
	// 				}
	// 			}
	// 		}
	// 	}
	// 	upBackendsString := fmt.Sprintf("%d", upBackends)
	// 	if downBackends != 0 {
	// 		upBackendsString = console.Colorize("InfoFail", fmt.Sprintf("%d", upBackends))
	// 	}
	// 	msg += fmt.Sprintf("Drives: %s/%d %s\n", upBackendsString,
	// 		upBackends+downBackends, console.Colorize("Info", "OK"))
	// }
	return
}

// JSON jsonified service status message.
func (u infoMessage) JSON() string {
	// u.Status = "success"
	statusJSONBytes, e := json.MarshalIndent(u, "", "    ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(statusJSONBytes)
}

// checkAdminInfoSyntax - validate all the passed arguments
func checkAdminServerInfoSyntax(ctx *cli.Context) {
	if len(ctx.Args()) == 0 || len(ctx.Args()) > 1 {
		cli.ShowCommandHelpAndExit(ctx, "info", 1) // last argument is exit code
	}
}

func mainAdminInfo(ctx *cli.Context) error {
	checkAdminServerInfoSyntax(ctx)

	console.SetColor("Info", color.New(color.FgGreen, color.Bold))
	console.SetColor("InfoDegraded", color.New(color.FgYellow, color.Bold))
	console.SetColor("InfoFail", color.New(color.FgRed, color.Bold))

	// Get the alias parameter from cli
	args := ctx.Args()
	aliasedURL := args.Get(0)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	// printOfflineErrorMessage := func(err error) {
	// 	errMsg := ""
	// 	if err != nil {
	// 		errMsg = err.Error()
	// 	}
	// 	printMsg(infoMessage{
	// 		Addr:    aliasedURL,
	// 		Service: "off",
	// 		Err:     errMsg,
	// 	})
	// }

	processErr := func(e error) error {
		switch e.(type) {
		case *json.SyntaxError:
			println("Error:", e)
			return e
		case *url.Error:
			println("Error:", e)
			return e
		default:
			// If the error is not nil and unrecognized, just print it and exit
			fatalIf(probe.NewError(e), "Cannot get service status.")
		}
		return nil
	}

	// infoMessage, err = client.
	// 	// Fetch info of all servers (cluster or single server)
	infoMessage, e := client.ServerAdminInfo()
	if err := processErr(e); err != nil {
		// exit immediately if error encountered
		return nil
	}

	// 	// Fetch storage info of all servers (cluster or single server)
	// 	storageInfo, e := client.StorageInfo()
	// 	if err := processErr(e); err != nil {
	// 		// exit immediately if error encountered
	// 		return nil
	// 	}

	// 	// Fetch info of all CPU loads (all MinIO server instances)
	// 	cpuLoads, e := client.ServerCPULoadInfo()
	// 	if err := processErr(e); err != nil {
	// 		// exit immediately if error encountered
	// 		return nil
	// 	}

	// 	// Fetch info on memory usage (all MinIO server instances)
	// 	memUsages, e := client.ServerMemUsageInfo()
	// 	if err := processErr(e); err != nil {
	// 		// exit immediately if error encountered
	// 		return nil
	// 	}

	// 	// Construct the admin info structure that'll be displayed
	// 	// to the user
	// 	infoMessages := []infoMessage{}

	// 	// Construct server information
	// 	srvsInfo := []serverStruct{}

	// 	for i, serverInfo := range serversInfo {
	// 		srvInfo := serverStruct{}
	// 		srvInfo.Endpoint = serverInfo.Addr
	// 		srvInfo.Uptime = serverInfo.Data.Properties.Uptime
	// 		srvInfo.Version = serverInfo.Data.Properties.Version
	// 		srvInfo.CommitID = serverInfo.Data.Properties.CommitID
	// 		srvInfo.CPULoads = cpuLoads[i]
	// 		srvInfo.MemUsages = memUsages[i]
	// 		srvInfo.ConnStats = serverInfo.Data.ConnStats
	// 		srvsInfo = append(srvsInfo, srvInfo)

	// 		// Print the error if exists and jump to the next server
	// 		if serverInfo.Error != "" {

	// 			infoMessages = append(infoMessages, infoMessage{
	// 				Service: "on",
	// 				Addr:    serverInfo.Addr,
	// 				Err:     serverInfo.Error,
	// 			})
	// 			continue
	// 		}

	// 		// Construct the backend status
	// 		var storageInfoStat interface{}

	// 		if storageInfo.Backend.Type == madmin.Erasure {
	// 			storageInfoStat = xlBackend{
	// 				Type:         erasureType,
	// 				OnlineDisks:  filterPerNode(serverInfo.Addr, storageInfo.Backend.OnlineDisks),
	// 				OfflineDisks: filterPerNode(serverInfo.Addr, storageInfo.Backend.OfflineDisks),
	// 				Sets:         storageInfo.Backend.Sets,
	// 			}
	// 		} else {
	// 			storageInfoStat = fsBackend{
	// 				Type: fsType,
	// 			}
	// 		}

	// 		infoMessages = append(infoMessages, infoMessage{
	// 			Service:      "on",
	// 			Addr:         serverInfo.Addr,
	// 			Region:       serverInfo.Data.Properties.Region,
	// 			SQSARN:       serverInfo.Data.Properties.SQSARN,
	// 			DeploymentID: serverInfo.Data.Properties.DeploymentID,
	// 			Err:          serverInfo.Error,
	// 			StorageInfo:  storageInfoStat,
	// 			ServersInfo:  srvsInfo,
	// 		})

	// 	}

	// sort.Stable(&sortInfoWrapper{infoMessage})
	// for _, s := range infoMessage {
	printMsg(infoMessage)
	// 	}
	return nil
}

// type sortInfoWrapper struct {
// 	infos []infoMessage
// }

// func (s *sortInfoWrapper) Len() int {
// 	return len(s.infos)
// }

// func (s *sortInfoWrapper) Swap(i, j int) {
// 	if s.infos != nil {
// 		s.infos[i], s.infos[j] = s.infos[j], s.infos[i]
// 	}
// }

// func (s *sortInfoWrapper) Less(i, j int) bool {
// 	if s.infos != nil {
// 		return s.infos[i].Addr < s.infos[j].Addr
// 	}
// 	return false

// }
