/*
 * MinIO Client (C) 2019-2020 MinIO, Inc.
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
	"context"
	"fmt"
	"strconv"
	"time"

	json "github.com/minio/mc/pkg/colorjson"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio/pkg/console"
)

// Structured message depending on the type of console.
type retentionCmdMessage struct {
	Op        string              `json:"op"`
	Mode      minio.RetentionMode `json:"mode"`
	Validity  string              `json:"validity"`
	URLPath   string              `json:"urlpath"`
	VersionID string              `json:"versionID"`
	Status    string              `json:"status"`
	Err       error               `json:"error"`
}

// Colorized message for console printing.
func (m retentionCmdMessage) String() string {
	var color, msg string
	ed := ""
	if m.Op == "clear" {
		ed = "ed"
	}

	if m.Err != nil {
		color = "RetentionFailure"
		msg = fmt.Sprintf("Unable to %s object retention on `%s`: %s", m.Op, m.URLPath, m.Err)
	} else {
		color = "RetentionSuccess"
		msg = fmt.Sprintf("Object retention successfully %s%s for `%s`", m.Op, ed, m.URLPath)
	}
	if m.VersionID != "" {
		msg += fmt.Sprintf(" (version-id=%s)", m.VersionID)
	}
	msg += "."
	return console.Colorize(color, msg)
}

// JSON'ified message for scripting.
func (m retentionCmdMessage) JSON() string {
	if m.Err != nil {
		m.Status = "failure"
	}
	msgBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")
	return string(msgBytes)
}

// Structured message depending on the type of console.
type lockCmdMessage struct {
	Enabled  string              `json:"enabled"`
	Mode     minio.RetentionMode `json:"mode"`
	Validity string              `json:"validity"`
	Status   string              `json:"status"`
}

// Colorized message for console printing.
func (m lockCmdMessage) String() string {
	if m.Mode == "" {
		return console.Colorize("Clear", "Object lock configuration cleared successfully")
	}

	return fmt.Sprintf("%s mode is enabled for %s", console.Colorize("Mode", m.Mode), console.Colorize("Validity", m.Validity))
}

// JSON'ified message for scripting.
func (m lockCmdMessage) JSON() string {
	msgBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")
	return string(msgBytes)
}

func getRetainUntilDate(validity uint64, unit minio.ValidityUnit) (string, *probe.Error) {
	if validity == 0 {
		return "", probe.NewError(fmt.Errorf("invalid validity '%v'", validity))
	}
	t := UTCNow()
	if unit == minio.Years {
		t = t.AddDate(int(validity), 0, 0)
	} else {
		t = t.AddDate(0, 0, int(validity))
	}
	timeStr := t.Format(time.RFC3339)

	return timeStr, nil
}

func setRetentionSingle(ctx context.Context, op, alias, url, versionID string, mode minio.RetentionMode, retainUntil time.Time, bypassGovernance bool) *probe.Error {
	newClnt, err := newClientFromAlias(alias, url)
	if err != nil {
		return err
	}

	msg := retentionCmdMessage{
		Op:        op,
		Mode:      mode,
		URLPath:   urlJoinPath(alias, url),
		VersionID: versionID,
	}

	err = newClnt.PutObjectRetention(ctx, versionID, mode, retainUntil, bypassGovernance)
	if err != nil {
		msg.Err = err.ToGoError()
		msg.Status = "failure"
	} else {
		msg.Status = "success"
	}

	printMsg(msg)
	return err
}

func parseRetentionValidity(validityStr string) (uint64, minio.ValidityUnit, *probe.Error) {
	unitStr := string(validityStr[len(validityStr)-1])
	validityStr = validityStr[:len(validityStr)-1]
	validity, e := strconv.ParseUint(validityStr, 10, 64)
	if e != nil {
		return 0, "", probe.NewError(e).Trace(validityStr)
	}

	var unit minio.ValidityUnit
	switch unitStr {
	case "d", "D":
		unit = minio.Days
	case "y", "Y":
		unit = minio.Years
	default:
		return 0, "", errInvalidArgument().Trace(unitStr)
	}

	return validity, unit, nil
}

// Check if the bucket corresponding to the target url has
// object locking enabled, this to show a pretty error message
func checkObjectLockSupport(ctx context.Context, aliasedURL string) {
	clnt, err := newClient(aliasedURL)
	if err != nil {
		fatalIf(err.Trace(), "Unable to parse the provided url.")
	}

	status, _, _, _, err := clnt.GetObjectLockConfig(ctx)
	if err != nil {
		fatalIf(err.Trace(), "Unable to get bucket object lock configuration from `%s`", aliasedURL)
	}

	if status != "Enabled" {
		fatalIf(errDummy().Trace(), "Remote bucket does not support locking `%s`", aliasedURL)
	}
}

// Apply Retention for one object/version or many objects within a given prefix.
func applyRetention(ctx context.Context, op, target, versionID string, timeRef time.Time, withOlderVersions, isRecursive bool,
	mode minio.RetentionMode, validity uint64, unit minio.ValidityUnit, bypassGovernance bool) error {
	clnt, err := newClient(target)
	if err != nil {
		fatalIf(err.Trace(), "Unable to parse the provided url.")
	}

	// Quit early if urlStr does not point to an S3 server
	switch clnt.(type) {
	case *S3Client:
	default:
		fatal(errDummy().Trace(), "Retention is supported only for S3 servers.")
	}

	var until time.Time
	if mode != "" {
		timeStr, err := getRetainUntilDate(validity, unit)
		if err != nil {
			return err.ToGoError()

		}
		var e error
		until, e = time.Parse(time.RFC3339, timeStr)
		if e != nil {
			return e
		}
	}

	alias, urlStr, _ := mustExpandAlias(target)
	if versionID != "" || !isRecursive && !withOlderVersions {
		err := setRetentionSingle(ctx, op, alias, urlStr, versionID, mode, until, bypassGovernance)
		fatalIf(err.Trace(), "Unable to set retention on `%s`", target)
		return nil
	}

	lstOptions := ListOptions{isRecursive: isRecursive, showDir: DirNone}
	if !timeRef.IsZero() {
		lstOptions.withOlderVersions = withOlderVersions
		lstOptions.withDeleteMarkers = true
		lstOptions.timeRef = timeRef
	}

	var cErr error
	var atLeastOneRetentionApplied bool

	for content := range clnt.List(ctx, lstOptions) {
		if content.Err != nil {
			errorIf(content.Err.Trace(clnt.GetURL().String()), "Unable to list folder.")
			cErr = exitStatus(globalErrorExitStatus) // Set the exit status.
			continue
		}

		// The spec does not allow setting retention on delete marker
		if content.IsDeleteMarker {
			continue
		}

		if !isRecursive && alias+getKey(content) != getStandardizedURL(target) {
			break
		}

		err := setRetentionSingle(ctx, op, alias, content.URL.String(), content.VersionID, mode, until, bypassGovernance)
		if err != nil {
			errorIf(err.Trace(clnt.GetURL().String()), "Invalid URL")
			continue
		}

		atLeastOneRetentionApplied = true
	}

	if !atLeastOneRetentionApplied {
		errorIf(errDummy().Trace(clnt.GetURL().String()), "Unable to find any object/version to "+op+" its retention.")
		cErr = exitStatus(globalErrorExitStatus) // Set the exit status.
	}

	return cErr
}

// applyBucketLock - set object lock configuration.
func applyBucketLock(op string, urlStr string, mode minio.RetentionMode, validity uint64, unit minio.ValidityUnit) error {
	client, err := newClient(urlStr)
	if err != nil {
		fatalIf(err.Trace(), "Unable to parse the provided url.")
	}

	ctx, cancelLock := context.WithCancel(globalContext)
	defer cancelLock()
	if op == "clear" || mode != "" {
		err = client.SetObjectLockConfig(ctx, mode, validity, unit)
		fatalIf(err, "Unable to apply object lock configuration on the specified bucket.")
	} else {
		_, mode, validity, unit, err = client.GetObjectLockConfig(ctx)
		fatalIf(err, "Unable to apply object lock configuration on the specified bucket.")
	}

	printMsg(lockCmdMessage{
		Enabled:  "Enabled",
		Mode:     mode,
		Validity: fmt.Sprintf("%d%s", validity, unit),
		Status:   "success",
	})

	return nil
}

// showBucketLock - show object lock configuration.
func showBucketLock(urlStr string) error {
	client, err := newClient(urlStr)
	if err != nil {
		fatalIf(err.Trace(), "Unable to parse the provided url.")
	}

	ctx, cancelLock := context.WithCancel(globalContext)
	defer cancelLock()

	status, mode, validity, unit, err := client.GetObjectLockConfig(ctx)
	fatalIf(err, "Unable to get object lock configuration on the specified bucket.")

	printMsg(lockCmdMessage{
		Enabled:  status,
		Mode:     mode,
		Validity: fmt.Sprintf("%d%s", validity, unit),
		Status:   "success",
	})

	return nil
}
