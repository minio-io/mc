// Copyright (c) 2015-2022 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/dustin/go-humanize"

	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/notification"
	"github.com/minio/pkg/v3/console"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// mirror specific flags.
var (
	mirrorFlags = []cli.Flag{
		cli.BoolFlag{
			Name:   "force",
			Usage:  "force allows forced overwrite or removal of object(s) on target",
			Hidden: true, // Hidden since this option is deprecated.
		},
		cli.BoolFlag{
			Name:  "overwrite",
			Usage: "overwrite object(s) on target if it differs from source",
		},
		cli.BoolFlag{
			Name:   "fake",
			Usage:  "perform a fake mirror operation",
			Hidden: true, // deprecated 2022
		},
		cli.BoolFlag{
			Name:  "dry-run",
			Usage: "perform a fake mirror operation",
		},
		cli.BoolFlag{
			Name:  "watch, w",
			Usage: "watch and synchronize changes",
		},
		cli.BoolFlag{
			Name:  "remove",
			Usage: "remove extraneous object(s) on target",
		},
		cli.StringFlag{
			Name:  "region",
			Usage: "specify region when creating new bucket(s) on target",
			Value: "us-east-1",
		},
		cli.BoolFlag{
			Name:  "preserve, a",
			Usage: "preserve file(s)/object(s) attributes and bucket(s) policy/locking configuration(s) on target bucket(s)",
		},
		cli.BoolFlag{
			Name:   "md5",
			Usage:  "force all upload(s) to calculate md5sum checksum",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:   "multi-master",
			Usage:  "enable multi-master multi-site setup",
			Hidden: true,
		},
		cli.BoolFlag{
			Name:  "active-active",
			Usage: "enable active-active multi-site setup",
		},
		cli.BoolFlag{
			Name:  "disable-multipart",
			Usage: "disable multipart upload feature",
		},
		cli.StringSliceFlag{
			Name:  "exclude",
			Usage: "exclude object(s) that match specified object name pattern",
		},
		cli.StringSliceFlag{
			Name:  "exclude-bucket",
			Usage: "exclude bucket(s) that match specified bucket name pattern",
		},
		cli.StringSliceFlag{
			Name:  "include-bucket",
			Usage: "mirror bucket(s) that match specified bucket name pattern",
		},
		cli.StringSliceFlag{
			Name:  "exclude-storageclass",
			Usage: "exclude object(s) that match the specified storage class",
		},
		cli.StringFlag{
			Name:  "older-than",
			Usage: "filter object(s) older than value in duration string (e.g. 7d10h31s)",
		},
		cli.StringFlag{
			Name:  "newer-than",
			Usage: "filter object(s) newer than value in duration string (e.g. 7d10h31s)",
		},
		cli.StringFlag{
			Name:  "storage-class, sc",
			Usage: "specify storage class for new object(s) on target",
		},
		cli.StringFlag{
			Name:  "attr",
			Usage: "add custom metadata for all objects",
		},
		cli.StringFlag{
			Name:  "monitoring-address",
			Usage: "if specified, a new prometheus endpoint will be created to report mirroring activity. (eg: localhost:8081)",
		},
		cli.BoolFlag{
			Name:  "retry",
			Usage: "if specified, will enable retrying on a per object basis if errors occur",
		},
		cli.BoolFlag{
			Name:  "summary",
			Usage: "print a summary of the mirror session",
		},
		cli.BoolFlag{
			Name:  "skip-errors",
			Usage: "skip any errors when mirroring",
		},
		checksumFlag,
	}
)

// Mirror folders recursively from a single source to many destinations
var mirrorCmd = cli.Command{
	Name:         "mirror",
	Usage:        "synchronize object(s) to a remote site",
	Action:       mainMirror,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(append(mirrorFlags, encFlags...), globalFlags...),
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] SOURCE TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}

ENVIRONMENT VARIABLES:
  MC_ENC_KMS: KMS encryption key in the form of (alias/prefix=key).
  MC_ENC_S3: S3 encryption key in the form of (alias/prefix=key).

EXAMPLES:
  01. Mirror a bucket recursively from MinIO cloud storage to a bucket on Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} play/photos/2014 s3/backup-photos

  02. Mirror a local folder recursively to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} backup/ s3/archive

  03. Only mirror files that are newer than 7 days, 10 hours and 30 minutes to Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --newer-than "7d10h30m" backup/ s3/archive

  04. Mirror a bucket from aliased Amazon S3 cloud storage to a folder on Windows.
      {{.Prompt}} {{.HelpName}} s3\documents\2014\ C:\backup\2014

  05. Mirror a bucket from aliased Amazon S3 cloud storage to a local folder use '--overwrite' to overwrite destination.
      {{.Prompt}} {{.HelpName}} --overwrite s3/miniocloud miniocloud-backup

  06. Mirror a bucket from MinIO cloud storage to a bucket on Amazon S3 cloud storage and remove any extraneous
      files on Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --remove play/photos/2014 s3/backup-photos/2014

  07. Continuously mirror a local folder recursively to MinIO cloud storage. '--watch' continuously watches for
      new objects, uploads and removes extraneous files on Amazon S3 cloud storage.
      {{.Prompt}} {{.HelpName}} --remove --watch /var/lib/backups play/backups

  08. Continuously mirror all buckets and objects from site 1 to site 2, removed buckets and objects will be reflected as well.
      {{.Prompt}} {{.HelpName}} --remove --watch site1-alias/ site2-alias/

  09. Mirror a bucket from aliased Amazon S3 cloud storage to a local folder.
      Exclude all .* files and *.temp files when mirroring.
      {{.Prompt}} {{.HelpName}} --exclude ".*" --exclude "*.temp" s3/test ~/test

  10. Mirror all buckets from aliased Amazon S3 cloud storage to a local folder.
      Exclude test* buckets and backup* buckets when mirroring.
      {{.Prompt}} {{.HelpName}} --exclude-bucket 'test*' --exclude 'backup*' s3 ~/test

  11. Mirror test* buckets from aliased Amazon S3 cloud storage to a local folder.
      {{.Prompt}} {{.HelpName}} --include-bucket 'test*' s3 ~/test

  12. Mirror objects newer than 10 days from bucket test to a local folder.
      {{.Prompt}} {{.HelpName}} --newer-than 10d s3/test ~/localfolder

  13. Mirror objects older than 30 days from Amazon S3 bucket test to a local folder.
      {{.Prompt}} {{.HelpName}} --older-than 30d s3/test ~/test

  14. Mirror server encrypted objects from Amazon S3 cloud storage to a bucket on Amazon S3 cloud storage
      {{.Prompt}} {{.HelpName}} --enc-c "minio/archive=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDA" --enc-c "s3/archive=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5BBB" s3/archive/ minio/archive/ 

  15. Update 'Cache-Control' header on all existing objects recursively.
      {{.Prompt}} {{.HelpName}} --attr "Cache-Control=max-age=90000,min-fresh=9000" myminio/video-files myminio/video-files

  16. Mirror a local folder recursively to Amazon S3 cloud storage and preserve all local file attributes.
      {{.Prompt}} {{.HelpName}} -a backup/ s3/archive

  17. Cross mirror between sites in a active-active deployment.
      Site-A: {{.Prompt}} {{.HelpName}} --active-active siteA siteB
      Site-B: {{.Prompt}} {{.HelpName}} --active-active siteB siteA
`,
}

var (
	mirrorTotalOps = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mc_mirror_total_s3ops",
		Help: "The total number of mirror operations",
	})
	mirrorTotalUploadedBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mc_mirror_total_s3uploaded_bytes",
		Help: "The total number of bytes uploaded",
	})
	mirrorFailedOps = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mc_mirror_failed_s3ops",
		Help: "The total number of failed mirror operations",
	})
	mirrorRestarts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "mc_mirror_total_restarts",
		Help: "The number of mirror restarts",
	})
	mirrorReplicationDurations = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "mc_mirror_replication_duration",
			Help:    "Histogram of replication time in ms per object sizes",
			Buckets: prometheus.ExponentialBuckets(1, 20, 5),
		},
		[]string{"object_size"},
	)
)

const uaMirrorAppName = "mc-mirror"

type mirrorJob struct {
	stopCh chan struct{}

	// the global watcher object, which receives notifications of created
	// and deleted files
	watcher *Watcher

	// Hold operation status information
	status Status

	parallel *ParallelManager

	// channel for status messages
	statusCh chan URLs

	TotalObjects int64
	TotalBytes   int64

	sourceURL string
	targetURL string

	opts mirrorOptions
}

// mirrorMessage container for file mirror messages
type mirrorMessage struct {
	Status     string                 `json:"status"`
	Source     string                 `json:"source"`
	Target     string                 `json:"target"`
	Size       int64                  `json:"size"`
	TotalCount int64                  `json:"totalCount"`
	TotalSize  int64                  `json:"totalSize"`
	EventTime  string                 `json:"eventTime"`
	EventType  notification.EventType `json:"eventType"`
}

// String colorized mirror message
func (m mirrorMessage) String() string {
	var msg string
	if m.EventTime != "" {
		msg = console.Colorize("Time", fmt.Sprintf("[%s] ", m.EventTime))
	}
	if m.EventType == notification.ObjectRemovedDelete {
		return msg + "Removed " + console.Colorize("Removed", fmt.Sprintf("`%s`", m.Target))
	}
	if m.EventTime == "" {
		return console.Colorize("Mirror", fmt.Sprintf("`%s` -> `%s`", m.Source, m.Target))
	}
	msg += console.Colorize("Size", fmt.Sprintf("%6s ", humanize.IBytes(uint64(m.Size))))
	msg += console.Colorize("Mirror", fmt.Sprintf("`%s` -> `%s`", m.Source, m.Target))
	return msg
}

// JSON jsonified mirror message
func (m mirrorMessage) JSON() string {
	m.Status = "success"
	mirrorMessageBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(mirrorMessageBytes)
}

func (mj *mirrorJob) doCreateBucket(ctx context.Context, sURLs URLs) URLs {
	if mj.opts.isFake {
		return sURLs.WithError(nil)
	}

	// Construct proper path with alias.
	aliasedURL := filepath.Join(sURLs.TargetAlias, sURLs.TargetContent.URL.Path)
	clnt, pErr := newClient(aliasedURL)
	if pErr != nil {
		return sURLs.WithError(pErr)
	}

	err := clnt.MakeBucket(ctx, "", mj.opts.isOverwrite, false)
	if err != nil {
		return sURLs.WithError(err)
	}

	return sURLs.WithError(nil)
}

func (mj *mirrorJob) doDeleteBucket(ctx context.Context, sURLs URLs) URLs {
	if mj.opts.isFake {
		return sURLs.WithError(nil)
	}

	// Construct proper path with alias.
	aliasedURL := filepath.Join(sURLs.TargetAlias, sURLs.TargetContent.URL.Path)
	clnt, pErr := newClient(aliasedURL)
	if pErr != nil {
		return sURLs.WithError(pErr)
	}

	contentCh := make(chan *ClientContent, 1)
	contentCh <- &ClientContent{URL: clnt.GetURL()}
	close(contentCh)

	for result := range clnt.Remove(ctx, false, true, false, false, contentCh) {
		if result.Err != nil {
			return sURLs.WithError(result.Err)
		}
	}

	return sURLs.WithError(nil)
}

// doRemove - removes files on target.
func (mj *mirrorJob) doRemove(ctx context.Context, sURLs URLs, event EventInfo) URLs {
	if mj.opts.isFake {
		return sURLs.WithError(nil)
	}

	// Construct proper path with alias.
	targetWithAlias := filepath.Join(sURLs.TargetAlias, sURLs.TargetContent.URL.Path)
	clnt, pErr := newClient(targetWithAlias)
	if pErr != nil {
		return sURLs.WithError(pErr)
	}
	if sURLs.SourceAlias != "" {
		clnt.AddUserAgent(uaMirrorAppName+":"+sURLs.SourceAlias, ReleaseTag)
	} else {
		clnt.AddUserAgent(uaMirrorAppName, ReleaseTag)
	}
	contentCh := make(chan *ClientContent, 1)
	contentCh <- &ClientContent{URL: *newClientURL(sURLs.TargetContent.URL.Path)}
	close(contentCh)
	isRemoveBucket := false
	resultCh := clnt.Remove(ctx, false, isRemoveBucket, false, false, contentCh)
	for result := range resultCh {
		if result.Err != nil {
			switch result.Err.ToGoError().(type) {
			case PathInsufficientPermission:
				// Ignore Permission error.
				continue
			}
			return sURLs.WithError(result.Err)
		}
		targetPath := filepath.ToSlash(filepath.Join(sURLs.TargetAlias, sURLs.TargetContent.URL.Path))
		mj.status.PrintMsg(mirrorMessage{
			Target:     targetPath,
			TotalCount: sURLs.TotalCount,
			TotalSize:  sURLs.TotalSize,
			EventTime:  event.Time,
			EventType:  event.Type,
		})
	}

	return sURLs.WithError(nil)
}

// doMirror - Mirror an object to multiple destination. URLs status contains a copy of sURLs and error if any.
func (mj *mirrorJob) doMirrorWatch(ctx context.Context, targetPath string, tgtSSE encrypt.ServerSide, sURLs URLs, event EventInfo) URLs {
	shouldQueue := false
	if !mj.opts.isOverwrite && !mj.opts.activeActive {
		targetClient, err := newClient(targetPath)
		if err != nil {
			// cannot create targetclient
			return sURLs.WithError(err)
		}
		_, err = targetClient.Stat(ctx, StatOptions{sse: tgtSSE})
		if err == nil {
			if !sURLs.SourceContent.RetentionEnabled && !sURLs.SourceContent.LegalHoldEnabled {
				return sURLs.WithError(probe.NewError(ObjectAlreadyExists{}))
			}
		} // doesn't exist
		shouldQueue = true
	}
	if shouldQueue || mj.opts.isOverwrite || mj.opts.activeActive {
		// adjust total, because we want to show progress of
		// the item still queued to be copied.
		mj.status.Add(sURLs.SourceContent.Size)
		mj.status.SetTotal(mj.status.Get()).Update()
		mj.status.AddCounts(1)
		sURLs.TotalSize = mj.status.Get()
		sURLs.TotalCount = mj.status.GetCounts()
		return mj.doMirror(ctx, sURLs, event)
	}
	return sURLs.WithError(probe.NewError(ObjectAlreadyExists{}))
}

func convertSizeToTag(size int64) string {
	switch {
	case size < 1024:
		return "LESS_THAN_1_KiB"
	case size < 1024*1024:
		return "LESS_THAN_1_MiB"
	case size < 10*1024*1024:
		return "LESS_THAN_10_MiB"
	case size < 100*1024*1024:
		return "LESS_THAN_100_MiB"
	case size < 1024*1024*1024:
		return "LESS_THAN_1_GiB"
	default:
		return "GREATER_THAN_1_GiB"
	}
}

// doMirror - Mirror an object to multiple destination. URLs status contains a copy of sURLs and error if any.
func (mj *mirrorJob) doMirror(ctx context.Context, sURLs URLs, event EventInfo) URLs {
	if sURLs.Error != nil { // Erroneous sURLs passed.
		return sURLs.WithError(sURLs.Error.Trace())
	}

	// For a fake mirror make sure we update respective progress bars
	// and accounting readers under relevant conditions.
	if mj.opts.isFake {
		if sURLs.SourceContent != nil {
			mj.status.Add(sURLs.SourceContent.Size)
		}
		mj.status.Update()
		return sURLs.WithError(nil)
	}

	sourceAlias := sURLs.SourceAlias
	sourceURL := sURLs.SourceContent.URL
	targetAlias := sURLs.TargetAlias
	targetURL := sURLs.TargetContent.URL
	length := sURLs.SourceContent.Size

	mj.status.SetCaption(sourceURL.String() + ":")

	// Initialize target metadata.
	sURLs.TargetContent.Metadata = make(map[string]string)

	if mj.opts.storageClass != "" {
		sURLs.TargetContent.StorageClass = mj.opts.storageClass
	}

	if mj.opts.activeActive {
		srcModTime := getSourceModTimeKey(sURLs.SourceContent.Metadata)
		// If the source object already has source modtime attribute set, then
		// use it in target. Otherwise use the S3 modtime instead.
		if srcModTime != "" {
			sURLs.TargetContent.Metadata[activeActiveSourceModTimeKey] = srcModTime
		} else {
			sURLs.TargetContent.Metadata[activeActiveSourceModTimeKey] = sURLs.SourceContent.Time.Format(time.RFC3339Nano)
		}
	}

	// Initialize additional target user metadata.
	sURLs.TargetContent.UserMetadata = mj.opts.userMetadata

	sourcePath := filepath.ToSlash(filepath.Join(sourceAlias, sourceURL.Path))
	targetPath := filepath.ToSlash(filepath.Join(targetAlias, targetURL.Path))
	if !mj.opts.isSummary {
		mj.status.PrintMsg(mirrorMessage{
			Source:     sourcePath,
			Target:     targetPath,
			Size:       length,
			TotalCount: sURLs.TotalCount,
			TotalSize:  sURLs.TotalSize,
			EventTime:  event.Time,
			EventType:  event.Type,
		})
	}
	sURLs.MD5 = mj.opts.md5
	sURLs.checksum = mj.opts.checksum
	sURLs.DisableMultipart = mj.opts.disableMultipart

	var ret URLs

	if !mj.opts.isRetriable {
		now := time.Now()
		ret = uploadSourceToTargetURL(ctx, uploadSourceToTargetURLOpts{urls: sURLs, progress: mj.status, encKeyDB: mj.opts.encKeyDB, preserve: mj.opts.isMetadata, isZip: false})
		if ret.Error == nil {
			durationMs := time.Since(now).Milliseconds()
			mirrorReplicationDurations.With(prometheus.Labels{"object_size": convertSizeToTag(sURLs.SourceContent.Size)}).Observe(float64(durationMs))
		}

		return ret
	}

	newRetryManager(ctx, time.Second, 3).retry(func(rm *retryManager) *probe.Error {
		if rm.retries > 0 {
			printMsg(retryMessage{
				SourceURL: sURLs.SourceContent.URL.String(),
				TargetURL: sURLs.TargetContent.URL.String(),
				Retries:   rm.retries,
			})
		}

		now := time.Now()
		ret = uploadSourceToTargetURL(ctx, uploadSourceToTargetURLOpts{urls: sURLs, progress: mj.status, encKeyDB: mj.opts.encKeyDB, preserve: mj.opts.isMetadata, isZip: false})
		if ret.Error == nil {
			durationMs := time.Since(now).Milliseconds()
			mirrorReplicationDurations.With(prometheus.Labels{"object_size": convertSizeToTag(sURLs.SourceContent.Size)}).Observe(float64(durationMs))
		}

		return ret.Error
	})

	return ret
}

// Update progress status
func (mj *mirrorJob) monitorMirrorStatus(cancel context.CancelFunc) (errDuringMirror bool) {
	// now we want to start the progress bar
	mj.status.Start()
	defer mj.status.Finish()

	var cancelInProgress bool

	for sURLs := range mj.statusCh {
		if cancelInProgress {
			// Do not need to print any error after
			// canceling the context, just draining
			// the status channel here.
			continue
		}

		// Update prometheus fields
		mirrorTotalOps.Inc()

		if sURLs.Error != nil {
			var ignoreErr bool

			switch {
			case sURLs.SourceContent != nil:
				if isErrIgnored(sURLs.Error) {
					ignoreErr = true
				} else {
					switch sURLs.Error.ToGoError().(type) {
					case PathInsufficientPermission:
						// Ignore Permission error.
						ignoreErr = true
					}
					if !ignoreErr {
						errorIf(sURLs.Error.Trace(sURLs.SourceContent.URL.String()),
							"Failed to copy `%s`.", sURLs.SourceContent.URL)
					}
				}
			case sURLs.TargetContent != nil:
				// When sURLs.SourceContent is nil, we know that we have an error related to removing
				errorIf(sURLs.Error.Trace(sURLs.TargetContent.URL.String()),
					"Failed to remove `%s`.", sURLs.TargetContent.URL.String())
			default:
				if strings.Contains(sURLs.Error.ToGoError().Error(), "Overwrite not allowed") {
					ignoreErr = true
				}
				if sURLs.ErrorCond == differInUnknown {
					errorIf(sURLs.Error.Trace(), "Failed to perform mirroring")
				} else {
					errorIf(sURLs.Error.Trace(),
						"Failed to perform mirroring, with error condition (%s)", sURLs.ErrorCond)
				}
			}

			if !ignoreErr {
				mirrorFailedOps.Inc()
				errDuringMirror = true
				// Quit mirroring if --skip-errors is not passed
				if !mj.opts.skipErrors {
					cancel()
					cancelInProgress = true
				}
			}

			continue
		}

		if sURLs.SourceContent != nil {
			mirrorTotalUploadedBytes.Add(float64(sURLs.SourceContent.Size))
		}
	}

	return
}

func (mj *mirrorJob) watchMirrorEvents(ctx context.Context, events []EventInfo) {
	for _, event := range events {
		// It will change the expanded alias back to the alias
		// again, by replacing the sourceUrlFull with the sourceAlias.
		// This url will be used to mirror.
		sourceAlias, sourceURLFull, _ := mustExpandAlias(mj.sourceURL)

		// If the passed source URL points to fs, fetch the absolute src path
		// to correctly calculate targetPath
		if sourceAlias == "" {
			tmpSrcURL, e := filepath.Abs(sourceURLFull)
			if e == nil {
				sourceURLFull = tmpSrcURL
			}
		}
		eventPath := event.Path
		if runtime.GOOS == "darwin" {
			// Strip the prefixes in the event path. Happens in darwin OS only
			eventPath = eventPath[strings.Index(eventPath, sourceURLFull):]
		} else if runtime.GOOS == "windows" {
			// Shared folder as source URL and if event path is an absolute path.
			eventPath = getEventPathURLWin(mj.sourceURL, eventPath)
		}

		sourceURL := newClientURL(eventPath)

		// build target path, it is the relative of the eventPath with the sourceUrl
		// joined to the targetURL.
		sourceSuffix := strings.TrimPrefix(eventPath, sourceURLFull)
		// Skip the object, if it matches the Exclude options provided
		if matchExcludeOptions(mj.opts.excludeOptions, sourceSuffix, sourceURL.Type) {
			continue
		}
		// Skip the bucket,  if it matches the provided exclude options or does not match the included options
		if matchBucketOptions(mj.opts.excludeBuckets, mj.opts.includeBuckets, sourceSuffix) {
			continue
		}

		sc, ok := event.UserMetadata["x-amz-storage-class"]
		if ok {
			var found bool
			for _, esc := range mj.opts.excludeStorageClasses {
				if esc == sc {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		targetPath := urlJoinPath(mj.targetURL, sourceSuffix)

		// newClient needs the unexpanded  path, newCLientURL needs the expanded path
		targetAlias, expandedTargetPath, _ := mustExpandAlias(targetPath)
		targetURL := newClientURL(expandedTargetPath)
		tgtSSE := getSSE(targetPath, mj.opts.encKeyDB[targetAlias])

		if strings.HasPrefix(string(event.Type), "s3:ObjectCreated:") {
			sourceModTime, _ := time.Parse(time.RFC3339Nano, event.Time)
			mirrorURL := URLs{
				SourceAlias: sourceAlias,
				SourceContent: &ClientContent{
					URL:              *sourceURL,
					RetentionEnabled: event.Type == notification.EventType("s3:ObjectCreated:PutRetention"),
					LegalHoldEnabled: event.Type == notification.EventType("s3:ObjectCreated:PutLegalHold"),
					Size:             event.Size,
					Time:             sourceModTime,
					Metadata:         event.UserMetadata,
				},
				TargetAlias:      targetAlias,
				TargetContent:    &ClientContent{URL: *targetURL},
				MD5:              mj.opts.md5,
				checksum:         mj.opts.checksum,
				DisableMultipart: mj.opts.disableMultipart,
				encKeyDB:         mj.opts.encKeyDB,
			}
			if mj.opts.activeActive &&
				event.Type != notification.ObjectCreatedCopy &&
				event.Type != notification.ObjectCreatedCompleteMultipartUpload &&
				(getSourceModTimeKey(mirrorURL.SourceContent.Metadata) != "" ||
					getSourceModTimeKey(mirrorURL.SourceContent.UserMetadata) != "") {
				// If source has active-active attributes, it means that the
				// object was uploaded by "mc mirror", hence ignore the event
				// to avoid copying it.
				continue
			}
			mj.parallel.queueTask(func() URLs {
				return mj.doMirrorWatch(ctx, targetPath, tgtSSE, mirrorURL, event)
			}, mirrorURL.SourceContent.Size)
		} else if event.Type == notification.ObjectRemovedDelete {
			if targetAlias != "" && strings.Contains(event.UserAgent, uaMirrorAppName+":"+targetAlias) {
				// Ignore delete cascading delete events if cyclical.
				continue
			}
			mirrorURL := URLs{
				SourceAlias:      sourceAlias,
				SourceContent:    nil,
				TargetAlias:      targetAlias,
				TargetContent:    &ClientContent{URL: *targetURL},
				MD5:              mj.opts.md5,
				checksum:         mj.opts.checksum,
				DisableMultipart: mj.opts.disableMultipart,
				encKeyDB:         mj.opts.encKeyDB,
			}
			mirrorURL.TotalCount = mj.status.GetCounts()
			mirrorURL.TotalSize = mj.status.Get()
			if mirrorURL.TargetContent != nil && (mj.opts.isRemove || mj.opts.activeActive) {
				mj.parallel.queueTask(func() URLs {
					return mj.doRemove(ctx, mirrorURL, event)
				}, 0)
			}
		} else if event.Type == notification.BucketCreatedAll {
			mirrorURL := URLs{
				SourceAlias:   sourceAlias,
				SourceContent: &ClientContent{URL: *sourceURL},
				TargetAlias:   targetAlias,
				TargetContent: &ClientContent{URL: *targetURL},
			}
			mj.parallel.queueTaskWithBarrier(func() URLs {
				return mj.doCreateBucket(ctx, mirrorURL)
			}, 0)
		} else if event.Type == notification.BucketRemovedAll && mj.opts.isRemove {
			mirrorURL := URLs{
				TargetAlias:   targetAlias,
				TargetContent: &ClientContent{URL: *targetURL},
			}
			mj.parallel.queueTaskWithBarrier(func() URLs {
				return mj.doDeleteBucket(ctx, mirrorURL)
			}, 0)
		}

	}
}

// this goroutine will watch for notifications, and add modified objects to the queue
func (mj *mirrorJob) watchMirror(ctx context.Context) {
	defer mj.watcher.Stop()

	for {
		select {
		case events, ok := <-mj.watcher.Events():
			if !ok {
				return
			}
			mj.watchMirrorEvents(ctx, events)
		case err, ok := <-mj.watcher.Errors():
			if !ok {
				return
			}
			switch err.ToGoError().(type) {
			case APINotImplemented:
				errorIf(err.Trace(),
					"Unable to Watch on source, perhaps source doesn't support Watching for events")
				return
			}
			if err != nil {
				mj.parallel.queueTask(func() URLs {
					return URLs{Error: err}
				}, 0)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (mj *mirrorJob) watchURL(ctx context.Context, sourceClient Client) *probe.Error {
	return mj.watcher.Join(ctx, sourceClient, true)
}

// Fetch urls that need to be mirrored
func (mj *mirrorJob) startMirror(ctx context.Context) {
	URLsCh := prepareMirrorURLs(ctx, mj.sourceURL, mj.targetURL, mj.opts)

	for {
		select {
		case sURLs, ok := <-URLsCh:
			if !ok {
				return
			}
			if sURLs.Error != nil {
				mj.statusCh <- sURLs
				continue
			}

			if sURLs.SourceContent != nil {
				if isOlder(sURLs.SourceContent.Time, mj.opts.olderThan) {
					continue
				}
				if isNewer(sURLs.SourceContent.Time, mj.opts.newerThan) {
					continue
				}
			}

			if sURLs.SourceContent != nil {
				mj.status.Add(sURLs.SourceContent.Size)
			}

			mj.status.SetTotal(mj.status.Get()).Update()
			mj.status.AddCounts(1)

			// Save total count.
			sURLs.TotalCount = mj.status.GetCounts()
			// Save totalSize.
			sURLs.TotalSize = mj.status.Get()

			if sURLs.SourceContent != nil {
				mj.parallel.queueTask(func() URLs {
					return mj.doMirror(ctx, sURLs, EventInfo{})
				}, sURLs.SourceContent.Size)
			} else if sURLs.TargetContent != nil && mj.opts.isRemove {
				mj.parallel.queueTask(func() URLs {
					return mj.doRemove(ctx, sURLs, EventInfo{})
				}, 0)
			}
		case <-ctx.Done():
			return
		case <-mj.stopCh:
			return
		}
	}
}

// when using a struct for copying, we could save a lot of passing of variables
func (mj *mirrorJob) mirror(ctx context.Context) bool {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)

	// Starts watcher loop for watching for new events.
	if mj.opts.isWatch {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mj.watchMirror(ctx)
		}()
	}

	// Start mirroring.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// startMirror locks and blocks itself.
		mj.startMirror(ctx)
	}()

	// Close statusCh when both watch & mirror quits
	go func() {
		wg.Wait()
		mj.parallel.stopAndWait()
		close(mj.statusCh)
	}()

	return mj.monitorMirrorStatus(cancel)
}

func newMirrorJob(srcURL, dstURL string, opts mirrorOptions) *mirrorJob {
	mj := mirrorJob{
		stopCh: make(chan struct{}),

		sourceURL: srcURL,
		targetURL: dstURL,
		opts:      opts,
		statusCh:  make(chan URLs),
		watcher:   NewWatcher(UTCNow()),
	}

	mj.parallel = newParallelManager(mj.statusCh)

	// we'll define the status to use here,
	// do we want the quiet status? or the progressbar
	if globalQuiet || opts.isSummary {
		mj.status = NewQuietStatus(mj.parallel)
	} else if globalJSON {
		mj.status = NewQuietStatus(mj.parallel)
	} else {
		mj.status = NewProgressStatus(mj.parallel)
	}

	return &mj
}

// copyBucketPolicies - copy policies from source to dest
func copyBucketPolicies(ctx context.Context, srcClt, dstClt Client, isOverwrite bool) *probe.Error {
	rules, err := srcClt.GetAccessRules(ctx)
	if err != nil {
		switch err.ToGoError().(type) {
		case APINotImplemented:
			return nil
		}
		return err
	}
	// Set found rules to target bucket if permitted
	for _, r := range rules {
		originalRule, _, err := dstClt.GetAccess(ctx)
		if err != nil {
			return err
		}
		// Set rule only if it doesn't exist in the target bucket
		// or force flag is activated
		if originalRule == "none" || isOverwrite {
			err = dstClt.SetAccess(ctx, r, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func getEventPathURLWin(srcURL, eventPath string) string {
	// A rename or move or sometimes even write event sets eventPath as an absolute filepath.
	// If the watch folder is a shared folder the write events show the entire event path,
	// from which we need to deduce the correct path relative to the source URL
	var eventRelPath, lastPathPrefix string
	var lastPathPrefixPos int
	sourceURLpathList := strings.Split(srcURL, slashSeperator)
	lenSrcURLSlice := len(sourceURLpathList)
	shdModifyEventPath := filepath.IsAbs(eventPath) && !filepath.IsAbs(srcURL) && lenSrcURLSlice > 1

	if shdModifyEventPath {
		lastPathPrefix = sourceURLpathList[lenSrcURLSlice-1]
		lastPathPrefixPos = strings.Index(eventPath, lastPathPrefix)
	}
	canModifyEventPath := shdModifyEventPath && lastPathPrefix != "" && lastPathPrefixPos > 0
	canModifyEventPath = canModifyEventPath && lastPathPrefixPos+len(lastPathPrefix) < len(eventPath)
	if canModifyEventPath {
		eventRelPath = filepath.ToSlash(eventPath[lastPathPrefixPos+len(lastPathPrefix):])
		eventPath = srcURL + eventRelPath
	}
	return eventPath
}

// runMirror - mirrors all buckets to another S3 server
func runMirror(ctx context.Context, srcURL, dstURL string, cli *cli.Context, encKeyDB map[string][]prefixSSEPair) bool {
	// Parse metadata.
	userMetadata := make(map[string]string)
	if cli.String("attr") != "" {
		var err *probe.Error
		userMetadata, err = getMetaDataEntry(cli.String("attr"))
		fatalIf(err, "Unable to parse attribute %v", cli.String("attr"))
	}

	srcClt, err := newClient(srcURL)
	fatalIf(err, "Unable to initialize `"+srcURL+"`.")

	dstClt, err := newClient(dstURL)
	fatalIf(err, "Unable to initialize `"+dstURL+"`.")

	// This is kept for backward compatibility, `--force` means --overwrite.
	isOverwrite := cli.Bool("force")
	if !isOverwrite {
		isOverwrite = cli.Bool("overwrite")
	}

	isWatch := cli.Bool("watch") || cli.Bool("multi-master") || cli.Bool("active-active")
	isRemove := cli.Bool("remove")
	md5, checksum := parseChecksum(cli)

	// preserve is also expected to be overwritten if necessary
	isMetadata := cli.Bool("a") || isWatch || len(userMetadata) > 0
	isFake := cli.Bool("fake") || cli.Bool("dry-run")

	mopts := mirrorOptions{
		isFake:                isFake,
		isRemove:              isRemove,
		isOverwrite:           isOverwrite,
		isWatch:               isWatch,
		isMetadata:            isMetadata,
		isSummary:             cli.Bool("summary"),
		isRetriable:           cli.Bool("retry"),
		md5:                   md5,
		checksum:              checksum,
		disableMultipart:      cli.Bool("disable-multipart"),
		skipErrors:            cli.Bool("skip-errors"),
		excludeOptions:        cli.StringSlice("exclude"),
		excludeBuckets:        cli.StringSlice("exclude-bucket"),
		includeBuckets:        cli.StringSlice("include-bucket"),
		excludeStorageClasses: cli.StringSlice("exclude-storageclass"),
		olderThan:             cli.String("older-than"),
		newerThan:             cli.String("newer-than"),
		storageClass:          cli.String("storage-class"),
		userMetadata:          userMetadata,
		encKeyDB:              encKeyDB,
		activeActive:          isWatch,
	}

	// Create a new mirror job and execute it
	mj := newMirrorJob(srcURL, dstURL, mopts)

	preserve := cli.Bool("preserve")

	createDstBuckets := dstClt.GetURL().Type == objectStorage && dstClt.GetURL().Path == string(dstClt.GetURL().Separator)
	mirrorSrcBuckets := srcClt.GetURL().Type == objectStorage && srcClt.GetURL().Path == string(srcClt.GetURL().Separator)
	mirrorBucketsToBuckets := mirrorSrcBuckets && createDstBuckets

	if mirrorSrcBuckets || createDstBuckets {
		// Synchronize buckets using dirDifference function
		for d := range bucketDifference(ctx, srcClt, dstClt) {
			if d.Error != nil {
				if mj.opts.activeActive {
					errorIf(d.Error, "Failed to start mirroring.. retrying")
					return true
				}
				mj.status.fatalIf(d.Error, "Failed to start mirroring.")
			}

			if d.Diff == differInSecond {
				diffBucket := strings.TrimPrefix(d.SecondURL, dstClt.GetURL().String())
				if !isFake && isRemove {
					aliasedDstBucket := path.Join(dstURL, diffBucket)
					err := deleteBucket(ctx, aliasedDstBucket, false)
					mj.status.fatalIf(err, "Failed to start mirroring.")
				}
				continue
			}

			sourceSuffix := strings.TrimPrefix(d.FirstURL, srcClt.GetURL().String())

			newSrcURL := path.Join(srcURL, sourceSuffix)
			newTgtURL := path.Join(dstURL, sourceSuffix)

			newSrcClt, _ := newClient(newSrcURL)
			newDstClt, _ := newClient(newTgtURL)

			if d.Diff == differInFirst {
				var (
					withLock bool
					mode     minio.RetentionMode
					validity uint64
					unit     minio.ValidityUnit
					err      *probe.Error
				)
				if preserve && mirrorBucketsToBuckets {
					_, mode, validity, unit, err = newSrcClt.GetObjectLockConfig(ctx)
					if err == nil {
						withLock = true
					}
				}

				mj.status.PrintMsg(mirrorMessage{
					Source: newSrcURL,
					Target: newTgtURL,
				})

				if mj.opts.isFake {
					continue
				}

				// Skips bucket creation if it matches the provided exclusion options or does not match the included options
				if matchBucketOptions(mopts.excludeBuckets, mj.opts.includeBuckets, sourceSuffix) {
					continue
				}

				// Bucket only exists in the source, create the same bucket in the destination
				if err := newDstClt.MakeBucket(ctx, cli.String("region"), false, withLock); err != nil {
					errorIf(err, "Unable to create bucket at `%s`.", newTgtURL)
					continue
				}
				if preserve && mirrorBucketsToBuckets {
					// object lock configuration set on bucket
					if mode != "" {
						err = newDstClt.SetObjectLockConfig(ctx, mode, validity, unit)
						errorIf(err, "Unable to set object lock config in `%s`.", newTgtURL)
						if err != nil && mj.opts.activeActive {
							return true
						}
						if err == nil {
							mj.opts.md5 = true
							mj.opts.checksum = minio.ChecksumNone
						}
					}
					errorIf(copyBucketPolicies(ctx, newSrcClt, newDstClt, isOverwrite),
						"Unable to copy bucket policies to `%s`.", newDstClt.GetURL())
				}
			}
		}
	}

	if mj.opts.isWatch {
		// monitor mode will watch the source folders for changes,
		// and queue them for copying.
		if err := mj.watchURL(ctx, srcClt); err != nil {
			if mj.opts.activeActive {
				errorIf(err, "Failed to start monitoring.. retrying")
				return true
			}
			mj.status.fatalIf(err, "Failed to start monitoring.")
		}
	}

	return mj.mirror(ctx)
}

// Main entry point for mirror command.
func mainMirror(cliCtx *cli.Context) error {
	// Additional command specific theme customization.
	console.SetColor("Mirror", color.New(color.FgGreen, color.Bold))

	ctx, cancelMirror := context.WithCancel(globalContext)
	defer cancelMirror()

	encKeyDB, err := validateAndCreateEncryptionKeys(cliCtx)
	fatalIf(err, "Unable to parse encryption keys.")

	// check 'mirror' cli arguments.
	srcURL, tgtURL := checkMirrorSyntax(ctx, cliCtx, encKeyDB)

	if prometheusAddress := cliCtx.String("monitoring-address"); prometheusAddress != "" {
		http.Handle("/metrics", promhttp.Handler())
		go func() {
			if e := http.ListenAndServe(prometheusAddress, nil); e != nil {
				fatalIf(probe.NewError(e), "Unable to setup monitoring endpoint.")
			}
		}()
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for {
		select {
		case <-ctx.Done():
			return exitStatus(globalErrorExitStatus)
		default:
			errorDetected := runMirror(ctx, srcURL, tgtURL, cliCtx, encKeyDB)
			if cliCtx.Bool("watch") || cliCtx.Bool("multi-master") || cliCtx.Bool("active-active") {
				mirrorRestarts.Inc()
				time.Sleep(time.Duration(r.Float64() * float64(2*time.Second)))
				continue
			}
			if errorDetected {
				return exitStatus(globalErrorExitStatus)
			}
			return nil
		}
	}
}
