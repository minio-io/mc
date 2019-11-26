/*
 * MinIO Client (C) 2014-2019 MinIO, Inc.
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
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/minio/cli"
	"github.com/minio/mc/pkg/console"
	"github.com/minio/mc/pkg/probe"
)

// cp command flags.
var (
	cpFlags = []cli.Flag{
		cli.BoolFlag{
			Name:  "recursive, r",
			Usage: "copy recursively",
		},
		cli.StringFlag{
			Name:  "older-than",
			Usage: "copy objects older than L days, M hours and N minutes",
		},
		cli.StringFlag{
			Name:  "newer-than",
			Usage: "copy objects newer than L days, M hours and N minutes",
		},
		cli.StringFlag{
			Name:  "storage-class, sc",
			Usage: "set storage class for new object(s) on target",
		},
		cli.StringFlag{
			Name:  "encrypt",
			Usage: "encrypt/decrypt objects (using server-side encryption with server managed keys)",
		},
		cli.StringFlag{
			Name:  "attr",
			Usage: "add custom metadata for the object",
		},
		cli.BoolFlag{
			Name:  "continue, c",
			Usage: "create or resume copy session",
		},
		cli.BoolFlag{
			Name:  "preserve, a",
			Usage: "preserve filesystem attributes (mode, ownership, timestamps)",
		},
	}
)

// ErrInvalidMetadata reflects invalid metadata format
var ErrInvalidMetadata = errors.New("specified metadata should be of form key1=value1;key2=value2;... and so on")

// Copy command.
var cpCmd = cli.Command{
	Name:   "cp",
	Usage:  "copy objects",
	Action: mainCopy,
	Before: setGlobalsFromContext,
	Flags:  append(append(cpFlags, ioFlags...), globalFlags...),
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] SOURCE [SOURCE...] TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
ENVIRONMENT VARIABLES:
  MC_ENCRYPT:      list of comma delimited prefixes
  MC_ENCRYPT_KEY:  list of comma delimited prefix=secret values

EXAMPLES:
  01. Copy a list of objects from local file system to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} Music/*.ogg s3/jukebox/

  02. Copy a folder recursively from MinIO cloud storage to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --recursive play/mybucket/burningman2011/ s3/mybucket/

  03. Copy multiple local folders recursively to MinIO cloud storage.
      {{.Prompt}} {{.HelpName}} --recursive backup/2014/ backup/2015/ play/archive/

  04. Copy a bucket recursively from aliased Amazon S3 cloud storage to local filesystem on Windows.
      {{.Prompt}} {{.HelpName}} --recursive s3\documents\2014\ C:\Backups\2014

  05. Copy files older than 7 days and 10 hours from MinIO cloud storage to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --older-than 7d10h play/mybucket/burningman2011/ s3/mybucket/

  06. Copy files newer than 7 days and 10 hours from MinIO cloud storage to a local path.
      {{.Prompt}} {{.HelpName}} --newer-than 7d10h play/mybucket/burningman2011/ ~/latest/

  07. Copy an object with name containing unicode characters to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} 本語 s3/andoria/

  08. Copy a local folder with space separated characters to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --recursive 'workdir/documents/May 2014/' s3/miniocloud

  09. Copy a folder with encrypted objects recursively from Amazon S3 to MinIO cloud storage.
      {{.Prompt}} {{.HelpName}} --recursive --encrypt-key "s3/documents/=32byteslongsecretkeymustbegiven1,myminio/documents/=32byteslongsecretkeymustbegiven2" s3/documents/ myminio/documents/

  10. Copy a folder with encrypted objects recursively from Amazon S3 to MinIO cloud storage. In case the encryption key contains non-printable character like tab, pass the
      base64 encoded string as key.
      {{.Prompt}} {{.HelpName}} --recursive --encrypt-key "s3/documents/=MzJieXRlc2xvbmdzZWNyZWFiY2RlZmcJZ2l2ZW5uMjE=,myminio/documents/=MzJieXRlc2xvbmdzZWNyZWFiY2RlZmcJZ2l2ZW5uMjE=" s3/documents/ myminio/documents/

  11. Copy a list of objects from local file system to MinIO cloud storage with specified metadata.
      {{.Prompt}} {{.HelpName}} --attr key1=value1,key2=value2 Music/*.mp4 play/mybucket/

  12. Copy a folder recursively from MinIO cloud storage to Amazon S3 cloud storage with specified metadata.
      {{.Prompt}} {{.HelpName}} --attr Cache-Control=max-age=90000,min-fresh=9000\;key1=value1\;key2=value2 --recursive play/mybucket/burningman2011/ s3/mybucket/

  13. Copy a text file to an object storage and assign REDUCED_REDUNDANCY storage-class to the uploaded object.
      {{.Prompt}} {{.HelpName}} --storage-class REDUCED_REDUNDANCY myobject.txt play/mybucket

  14. Copy a text file to an object storage and create or resume copy session.
      {{.Prompt}} {{.HelpName}} --recursive --continue myobject.txt play/mybucket
	  
  15. Copy a text file to an object storage and preserve the file system attribute as metadata.
      {{.Prompt}} {{.HelpName}} -a myobject.txt play/mybucket
`,
}

// copyMessage container for file copy messages
type copyMessage struct {
	Status     string `json:"status"`
	Source     string `json:"source"`
	Target     string `json:"target"`
	Size       int64  `json:"size"`
	TotalCount int64  `json:"totalCount"`
	TotalSize  int64  `json:"totalSize"`
}

// String colorized copy message
func (c copyMessage) String() string {
	return console.Colorize("Copy", fmt.Sprintf("`%s` -> `%s`", c.Source, c.Target))
}

// JSON jsonified copy message
func (c copyMessage) JSON() string {
	c.Status = "success"
	copyMessageBytes, e := json.MarshalIndent(c, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(copyMessageBytes)
}

// Progress - an interface which describes current amount
// of data written.
type Progress interface {
	Get() int64
}

// ProgressReader can be used to update the progress of
// an on-going transfer progress.
type ProgressReader interface {
	io.Reader
	Progress
}

// doCopy - Copy a singe file from source to destination
func doCopy(ctx context.Context, cpURLs URLs, pg ProgressReader, encKeyDB map[string][]prefixSSEPair) URLs {
	if cpURLs.Error != nil {
		cpURLs.Error = cpURLs.Error.Trace()
		return cpURLs
	}

	sourceAlias := cpURLs.SourceAlias
	sourceURL := cpURLs.SourceContent.URL
	targetAlias := cpURLs.TargetAlias
	targetURL := cpURLs.TargetContent.URL
	length := cpURLs.SourceContent.Size

	if progressReader, ok := pg.(*progressBar); ok {
		progressReader.SetCaption(cpURLs.SourceContent.URL.String() + ": ")
	} else {
		sourcePath := filepath.ToSlash(filepath.Join(sourceAlias, sourceURL.Path))
		targetPath := filepath.ToSlash(filepath.Join(targetAlias, targetURL.Path))
		printMsg(copyMessage{
			Source:     sourcePath,
			Target:     targetPath,
			Size:       length,
			TotalCount: cpURLs.TotalCount,
			TotalSize:  cpURLs.TotalSize,
		})
	}
	return uploadSourceToTargetURL(ctx, cpURLs, pg, encKeyDB)
}

// doCopyFake - Perform a fake copy to update the progress bar appropriately.
func doCopyFake(cpURLs URLs, pg Progress) URLs {
	if progressReader, ok := pg.(*progressBar); ok {
		progressReader.ProgressBar.Add64(cpURLs.SourceContent.Size)
	}
	return cpURLs
}

// doPrepareCopyURLs scans the source URL and prepares a list of objects for copying.
func doPrepareCopyURLs(session *sessionV8, trapCh <-chan bool, cancelCopy context.CancelFunc) {
	// Separate source and target. 'cp' can take only one target,
	// but any number of sources.
	sourceURLs := session.Header.CommandArgs[:len(session.Header.CommandArgs)-1]
	targetURL := session.Header.CommandArgs[len(session.Header.CommandArgs)-1] // Last one is target

	var totalBytes int64
	var totalObjects int64

	// Access recursive flag inside the session header.
	isRecursive := session.Header.CommandBoolFlags["recursive"]

	// isPreserveAll := session.Header.CommandBoolFlags["a"]

	olderThan := session.Header.CommandStringFlags["older-than"]
	newerThan := session.Header.CommandStringFlags["newer-than"]
	encryptKeys := session.Header.CommandStringFlags["encrypt-key"]
	encrypt := session.Header.CommandStringFlags["encrypt"]
	encKeyDB, err := parseAndValidateEncryptionKeys(encryptKeys, encrypt)
	fatalIf(err, "Unable to parse encryption keys.")

	// Create a session data file to store the processed URLs.
	dataFP := session.NewDataWriter()

	var scanBar scanBarFunc
	if !globalQuiet && !globalJSON { // set up progress bar
		scanBar = scanBarFactory()
	}
	URLsCh := prepareCopyURLs(sourceURLs, targetURL, isRecursive, encKeyDB)
	done := false
	for !done {
		select {
		case cpURLs, ok := <-URLsCh:
			if !ok { // Done with URL preparation
				done = true
				break
			}
			if cpURLs.Error != nil {
				// Print in new line and adjust to top so that we don't print over the ongoing scan bar
				if !globalQuiet && !globalJSON {
					console.Eraseline()
				}
				if strings.Contains(cpURLs.Error.ToGoError().Error(), " is a folder.") {
					errorIf(cpURLs.Error.Trace(), "Folder cannot be copied. Please use `...` suffix.")
				} else {
					errorIf(cpURLs.Error.Trace(), "Unable to prepare URL for copying.")
				}
				break
			}

			jsonData, e := json.Marshal(cpURLs)
			if e != nil {
				session.Delete()
				fatalIf(probe.NewError(e), "Unable to prepare URL for copying. Error in JSON marshaling.")
			}

			// Skip objects older than --older-than parameter if specified
			if olderThan != "" && isOlder(cpURLs.SourceContent.Time, olderThan) {
				continue
			}

			// Skip objects newer than --newer-than parameter if specified
			if newerThan != "" && isNewer(cpURLs.SourceContent.Time, newerThan) {
				continue
			}

			fmt.Fprintln(dataFP, string(jsonData))
			if !globalQuiet && !globalJSON {
				scanBar(cpURLs.SourceContent.URL.String())
			}

			totalBytes += cpURLs.SourceContent.Size
			totalObjects++
		case <-trapCh:
			cancelCopy()
			// Print in new line and adjust to top so that we don't print over the ongoing scan bar
			if !globalQuiet && !globalJSON {
				console.Eraseline()
			}
			session.Delete() // If we are interrupted during the URL scanning, we drop the session.
			os.Exit(0)
		}
	}
	session.Header.TotalBytes = totalBytes
	session.Header.TotalObjects = totalObjects
	session.Save()
}

func doCopySession(session *sessionV8, encKeyDB map[string][]prefixSSEPair) error {
	trapCh := signalTrap(os.Interrupt, syscall.SIGTERM, syscall.SIGKILL)

	ctx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	if !session.HasData() {
		doPrepareCopyURLs(session, trapCh, cancelCopy)
	}

	// Prepare URL scanner from session data file.
	urlScanner := bufio.NewScanner(session.NewDataReader())
	// isCopied returns true if an object has been already copied
	// or not. This is useful when we resume from a session.
	isCopied := isLastFactory(session.Header.LastCopied)

	// Store a progress bar or an accounter
	var pg ProgressReader

	// Enable progress bar reader only during default mode.
	if !globalQuiet && !globalJSON { // set up progress bar
		pg = newProgressBar(session.Header.TotalBytes)
	} else {
		pg = newAccounter(session.Header.TotalBytes)
	}

	var quitCh = make(chan struct{})
	var statusCh = make(chan URLs)

	parallel, queueCh := newParallelManager(statusCh)

	go func() {
		gracefulStop := func() {
			close(queueCh)
			parallel.wait()
			close(statusCh)
		}

		for {
			select {
			case <-quitCh:
				gracefulStop()
				return
			default:
				if !urlScanner.Scan() {
					// No more entries, quit immediately
					gracefulStop()
					return
				}

				if e := urlScanner.Err(); e != nil {
					// Error while reading. quit immediately
					gracefulStop()
					return
				}

				var cpURLs URLs
				// Unmarshal copyURLs from each line. This expects each line to be
				// an entire JSON object.
				if e := json.Unmarshal([]byte(urlScanner.Text()), &cpURLs); e != nil {
					errorIf(probe.NewError(e), "Unable to unmarshal %s", urlScanner.Text())
					continue
				}

				// Save total count.
				cpURLs.TotalCount = session.Header.TotalObjects

				// Save totalSize.
				cpURLs.TotalSize = session.Header.TotalBytes

				// Initialize target metadata.
				cpURLs.TargetContent.Metadata = make(map[string]string)

				// Initialize target user metadata.
				cpURLs.TargetContent.UserMetadata = make(map[string]string)

				// Check and handle storage class if passed in command line args
				if _, ok := session.Header.CommandStringFlags["storage-class"]; ok {
					cpURLs.TargetContent.Metadata["X-Amz-Storage-Class"] = session.Header.CommandStringFlags["storage-class"]
				}

				// Check and handle metadata if passed in command line args
				if len(session.Header.UserMetaData) != 0 {
					for metaDataKey, metaDataVal := range session.Header.UserMetaData {
						cpURLs.TargetContent.UserMetadata[metaDataKey] = metaDataVal
					}
				}

				// If one needs to store the file system information by passing -a flag
				if preserve := (session.Header.CommandBoolFlags["preserve"]); preserve {
					attrValue, pErr := getFileAttrMeta(cpURLs, encKeyDB)
					if pErr != nil {
						errorIf(pErr, "Unable to fetch file meta info for %s", urlScanner.Text())
						continue
					}

					if attrValue != "" {
						cpURLs.TargetContent.Metadata["mc-attrs"] = attrValue
					}
				}
				// Verify if previously copied, notify progress bar.
				if isCopied(cpURLs.SourceContent.URL.String()) {
					queueCh <- func() URLs {
						return doCopyFake(cpURLs, pg)
					}
				} else {
					queueCh <- func() URLs {
						return doCopy(ctx, cpURLs, pg, encKeyDB)
					}
				}
			}
		}
	}()

	var retErr error

loop:
	for {
		select {
		case <-trapCh:
			close(quitCh)
			cancelCopy()
			// Receive interrupt notification.
			if !globalQuiet && !globalJSON {
				console.Eraseline()
			}
			session.CloseAndDie()
		case cpURLs, ok := <-statusCh:
			// Status channel is closed, we should return.
			if !ok {
				break loop
			}
			if cpURLs.Error == nil {
				session.Header.LastCopied = cpURLs.SourceContent.URL.String()
				session.Save()
			} else {

				// Set exit status for any copy error
				retErr = exitStatus(globalErrorExitStatus)

				// Print in new line and adjust to top so that we
				// don't print over the ongoing progress bar.
				if !globalQuiet && !globalJSON {
					console.Eraseline()
				}
				errorIf(cpURLs.Error.Trace(cpURLs.SourceContent.URL.String()),
					fmt.Sprintf("Failed to copy `%s`.", cpURLs.SourceContent.URL.String()))
				if isErrIgnored(cpURLs.Error) {
					continue loop
				}
				// For critical errors we should exit. Session
				// can be resumed after the user figures out
				// the  problem.
				session.copyCloseAndDie(session.Header.CommandBoolFlags["session"])
			}
		}
	}

	if progressReader, ok := pg.(*progressBar); ok {
		if progressReader.ProgressBar.Get() > 0 {
			progressReader.ProgressBar.Finish()
		}
	} else {
		if accntReader, ok := pg.(*accounter); ok {
			printMsg(accntReader.Stat())
		}
	}

	return retErr
}

// validate the passed metadataString and populate the map
func getMetaDataEntry(metadataString string) (map[string]string, *probe.Error) {
	metaDataMap := make(map[string]string)
	for _, metaData := range strings.Split(metadataString, ";") {
		metaDataEntry := strings.SplitN(metaData, "=", 2)
		if len(metaDataEntry) == 2 {
			metaDataMap[metaDataEntry[0]] = metaDataEntry[1]
		} else {
			return nil, probe.NewError(ErrInvalidMetadata)
		}
	}
	return metaDataMap, nil
}

// // validate the passed metadataString and populate the map
// func getStatToPreserve() (map[string]string, *probe.Error) {
// 	// Collect stat data to preserve all stats for the object
// 	statDataMap := make(map[string]string)
// 	statDataEntry := stat()
// 	for _, statData := range strings.Split(, ";") {
// 	statDataEntry := strings.SplitN(statData, "=", 2)
// 	if len(statDataEntry) == 2 {
// 		metaDataMap[statDataEntry[0]] = statDataEntry[1]
// 	} else {
// 		return nil, probe.NewError(ErrInvalidMetadata)
// 	}
// }

// mainCopy is the entry point for cp command.
func mainCopy(ctx *cli.Context) error {
	// Parse encryption keys per command.
	encKeyDB, err := getEncKeys(ctx)
	fatalIf(err, "Unable to parse encryption keys.")

	// Parse metadata.
	userMetaMap := make(map[string]string)
	if ctx.String("attr") != "" {
		userMetaMap, err = getMetaDataEntry(ctx.String("attr"))
		fatalIf(err, "Unable to parse attribute %v", ctx.String("attr"))
	}

	// Get stat info and populate "x-amz-meta-mc-attrs" if preserveAll
	// flag, "-a", is provided
	// statToPreserveMap := make(map[string]string)
	if ctx.String("a") != "" {
		// statToPreserveMap, err = getStatToPreserve()
		fatalIf(err, "Unable to collect file stats to preserve")
	}

	// check 'copy' cli arguments.
	checkCopySyntax(ctx, encKeyDB)

	// Additional command speific theme customization.
	console.SetColor("Copy", color.New(color.FgGreen, color.Bold))

	recursive := ctx.Bool("recursive")
	olderThan := ctx.String("older-than")
	newerThan := ctx.String("newer-than")
	// preserveAll := ctx.Bool("a")
	storageClass := ctx.String("storage-class")
	sseKeys := os.Getenv("MC_ENCRYPT_KEY")
	if key := ctx.String("encrypt-key"); key != "" {
		sseKeys = key
	}

	if sseKeys != "" {
		sseKeys, err = getDecodedKey(sseKeys)
		fatalIf(err, "Unable to parse encryption keys.")
	}
	sse := ctx.String("encrypt")

	sessionID := getHash("cp", ctx.Args())
	if ctx.Bool("continue") && isSessionExists(sessionID) {
		resumeSession(sessionID)
		return nil
	}

	session := newSessionV8(sessionID)
	session.Header.CommandType = "cp"
	session.Header.CommandBoolFlags["recursive"] = recursive
	session.Header.CommandStringFlags["older-than"] = olderThan
	session.Header.CommandStringFlags["newer-than"] = newerThan
	session.Header.CommandStringFlags["storage-class"] = storageClass
	session.Header.CommandStringFlags["encrypt-key"] = sseKeys
	session.Header.CommandStringFlags["encrypt"] = sse
	session.Header.CommandBoolFlags["session"] = ctx.Bool("continue")

	if ctx.Bool("preserve") {
		session.Header.CommandBoolFlags["preserve"] = ctx.Bool("preserve")
	}
	session.Header.UserMetaData = userMetaMap

	var e error
	if session.Header.RootPath, e = os.Getwd(); e != nil {
		session.Delete()
		fatalIf(probe.NewError(e), "Unable to get current working folder.")
	}

	// extract URLs.
	session.Header.CommandArgs = ctx.Args()
	e = doCopySession(session, encKeyDB)
	session.Delete()

	return e
}
