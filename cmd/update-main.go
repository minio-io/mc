/*
 * Minio Client (C) 2015 Minio, Inc.
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
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/minio/cli"
	"github.com/minio/mc/pkg/console"
	"github.com/minio/minio/pkg/probe"
)

// command specific flags.
var (
	updateFlags = []cli.Flag{
		cli.BoolFlag{
			Name:  "experimental, E",
			Usage: "Check experimental update.",
		},
	}
)

// Check for new software updates.
var updateCmd = cli.Command{
	Name:   "update",
	Usage:  "Check for new mc update.",
	Action: mainUpdate,
	Before: setGlobalsFromContext,
	Flags:  append(updateFlags, globalFlags...),
	CustomHelpTemplate: `Name:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}} [FLAGS]

FLAGS:
  {{range .Flags}}{{.}}
  {{end}}
EXAMPLES:
   1. Check for any new official release.
      $ {{.HelpName}}

   2. Check for any new experimental release.
      $ {{.HelpName}} --experimental

`,
}

// update URL endpoints.
const (
	mcUpdateStableURL       = "https://dl.minio.io/client/mc/release"
	mcUpdateExperimentalURL = "https://dl.minio.io/client/mc/experimental"
)

// updateMessage container to hold update messages.
type updateMessage struct {
	Status   string `json:"status"`
	Update   bool   `json:"update"`
	Download string `json:"downloadURL"`
	Version  string `json:"version"`
}

// String colorized update message.
func (u updateMessage) String() string {
	if !u.Update {
		return console.Colorize("Update", "You are already running the most recent version of ‘mc’.")
	}
	var msg string
	if runtime.GOOS == "windows" {
		msg = "Download " + u.Download
	} else {
		msg = "Download " + u.Download
	}
	msg, err := colorizeUpdateMessage(msg)
	fatalIf(err.Trace(msg), "Unable to colorize experimental update notification string ‘"+msg+"’.")
	return msg
}

// JSON jsonified update message.
func (u updateMessage) JSON() string {
	u.Status = "success"
	updateMessageJSONBytes, e := json.Marshal(u)
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(updateMessageJSONBytes)
}

func parseReleaseData(data string) (time.Time, *probe.Error) {
	releaseStr := strings.Fields(data)
	if len(releaseStr) < 2 {
		return time.Time{}, probe.NewError(errors.New("Update data malformed"))
	}
	releaseDate := releaseStr[1]
	releaseDateSplits := strings.SplitN(releaseDate, ".", 3)
	if len(releaseDateSplits) < 3 {
		return time.Time{}, probe.NewError(errors.New("Update data malformed"))
	}
	if releaseDateSplits[0] != "mc" {
		return time.Time{}, probe.NewError(errors.New("Update data malformed, missing mc tag"))
	}
	// "OFFICIAL" tag is still kept for backward compatibility, we should remove this for the next release.
	if releaseDateSplits[1] != "RELEASE" && releaseDateSplits[1] != "OFFICIAL" {
		return time.Time{}, probe.NewError(errors.New("Update data malformed, missing RELEASE tag"))
	}
	dateSplits := strings.SplitN(releaseDateSplits[2], "T", 2)
	if len(dateSplits) < 2 {
		return time.Time{}, probe.NewError(errors.New("Update data malformed, not in modified RFC3359 form"))
	}
	dateSplits[1] = strings.Replace(dateSplits[1], "-", ":", -1)
	date := strings.Join(dateSplits, "T")

	parsedDate, e := time.Parse(time.RFC3339, date)
	if e != nil {
		return time.Time{}, probe.NewError(e)
	}
	return parsedDate, nil
}

// verify updates for releases.
func getReleaseUpdate(updateURL string) (updateMsg updateMessage, errMsg string, err *probe.Error) {
	// Construct a new update url.
	newUpdateURLPrefix := updateURL + "/" + runtime.GOOS + "-" + runtime.GOARCH
	newUpdateURL := newUpdateURLPrefix + "/mc.shasum"

	// Instantiate a new client with 3 sec timeout.
	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	// Get the downloadURL.
	var downloadURL string
	switch runtime.GOOS {
	case "windows":
		// For windows and darwin.
		downloadURL = newUpdateURLPrefix + "/mc.exe"
	default:
		// For all other operating systems.
		downloadURL = newUpdateURLPrefix + "/mc"
	}

	data, e := client.Get(newUpdateURL)
	if e != nil {
		err = probe.NewError(e)
		errMsg = "Unable to read from update URL ‘" + newUpdateURL + "’."
		return updateMessage{}, errMsg, err
	}
	if strings.HasPrefix(Version, "DEVELOPMENT.GOGET") {
		err = errDummy().Trace(newUpdateURL)
		errMsg = "Update mechanism is not supported for ‘go get’ based binary builds.  Please download official releases from https://minio.io/#minio"
		return updateMessage{}, errMsg, err
	}

	current, e := time.Parse(time.RFC3339, Version)
	if e != nil {
		err = probe.NewError(e)
		errMsg = "Unable to parse version string as time."
		return updateMessage{}, errMsg, err
	}

	if current.IsZero() {
		err = errDummy().Trace(newUpdateURL)
		errMsg = "Updates not supported for custom builds. Version field is empty. Please download official releases from https://minio.io/#minio"
		return updateMessage{}, errMsg, err
	}

	body, e := ioutil.ReadAll(data.Body)
	if e != nil {
		err = probe.NewError(e)
		errMsg = "Fetching updates failed. Please try again."
		return updateMessage{}, errMsg, err
	}

	latest, err := parseReleaseData(string(body))
	if err != nil {
		errMsg = "Please report this issue at https://github.com/minio/mc/issues."
		return updateMessage{}, errMsg, err.Trace(newUpdateURL)
	}

	if latest.IsZero() {
		err = errDummy().Trace(newUpdateURL)
		errMsg = "Unable to validate any update available at this time. Please open an issue at https://github.com/minio/mc/issues"
		return updateMessage{}, errMsg, err
	}

	updateMsg = updateMessage{
		Download: downloadURL,
		Version:  Version,
	}
	if latest.After(current) {
		updateMsg.Update = true
	}
	return updateMsg, "", nil
}

// main entry point for update command.
func mainUpdate(ctx *cli.Context) error {

	// Additional command speific theme customization.
	console.SetColor("Update", color.New(color.FgGreen, color.Bold))

	var updateMsg updateMessage
	var errMsg string
	var err *probe.Error
	// Check for update.
	if ctx.Bool("experimental") {
		updateMsg, errMsg, err = getReleaseUpdate(mcUpdateExperimentalURL)
	} else {
		updateMsg, errMsg, err = getReleaseUpdate(mcUpdateStableURL)
	}
	fatalIf(err, errMsg)
	printMsg(updateMsg)
	return nil
}
