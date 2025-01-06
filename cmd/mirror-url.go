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
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/minio/cli"
	"github.com/minio/minio-go/v7"
	"github.com/minio/pkg/v3/wildcard"
)

//
//   * MIRROR ARGS - VALID CASES
//   =========================
//   mirror(d1..., d2) -> []mirror(d1/f, d2/d1/f)

// checkMirrorSyntax(URLs []string)
func checkMirrorSyntax(ctx context.Context, cliCtx *cli.Context, encKeyDB map[string][]prefixSSEPair) (srcURL, tgtURL string) {
	if len(cliCtx.Args()) != 2 {
		showCommandHelpAndExit(cliCtx, 1) // last argument is exit code.
	}
	parseChecksum(cliCtx)

	// extract URLs.
	URLs := cliCtx.Args()
	srcURL = URLs[0]
	tgtURL = URLs[1]

	if cliCtx.Bool("force") && cliCtx.Bool("remove") {
		errorIf(errInvalidArgument().Trace(URLs...), "`--force` is deprecated, please use `--overwrite` instead with `--remove` for the same functionality.")
	} else if cliCtx.Bool("force") {
		errorIf(errInvalidArgument().Trace(URLs...), "`--force` is deprecated, please use `--overwrite` instead for the same functionality.")
	}

	_, expandedSourcePath, _ := mustExpandAlias(srcURL)
	srcClient := newClientURL(expandedSourcePath)
	_, expandedTargetPath, _ := mustExpandAlias(tgtURL)
	destClient := newClientURL(expandedTargetPath)

	// Mirror with preserve option on windows
	// only works for object storage to object storage
	if runtime.GOOS == "windows" && cliCtx.Bool("a") {
		if srcClient.Type == fileSystem || destClient.Type == fileSystem {
			errorIf(errInvalidArgument(), "Preserve functionality on windows support object storage to object storage transfer only.")
		}
	}

	/****** Generic rules *******/
	if !cliCtx.Bool("watch") && !cliCtx.Bool("active-active") && !cliCtx.Bool("multi-master") {
		_, srcContent, err := url2Stat(ctx, url2StatOptions{urlStr: srcURL, versionID: "", fileAttr: false, encKeyDB: encKeyDB, timeRef: time.Time{}, isZip: false, ignoreBucketExistsCheck: false})
		if err != nil {
			fatalIf(err.Trace(srcURL), "Unable to stat source `"+srcURL+"`.")
		}

		if !srcContent.Type.IsDir() {
			fatalIf(errInvalidArgument().Trace(srcContent.URL.String(), srcContent.Type.String()), fmt.Sprintf("Source `%s` is not a folder. Only folders are supported by mirror command.", srcURL))
		}

		if srcClient.Type == fileSystem && !filepath.IsAbs(srcURL) {
			origSrcURL := srcURL
			var e error
			// Changing relative path to absolute path, if it is a local directory.
			// Save original in case of error
			if srcURL, e = filepath.Abs(srcURL); e != nil {
				srcURL = origSrcURL
			}
		}
	}

	return
}

func matchExcludeOptions(excludeOptions []string, srcSuffix string, typ ClientURLType) bool {
	// if type is file system, remove leading slash
	if typ == fileSystem {
		if strings.HasPrefix(srcSuffix, "/") {
			srcSuffix = srcSuffix[1:]
		} else if runtime.GOOS == "windows" && strings.HasPrefix(srcSuffix, `\`) {
			srcSuffix = srcSuffix[1:]
		}
	}
	for _, pattern := range excludeOptions {
		if wildcard.Match(pattern, srcSuffix) {
			return true
		}
	}
	return false
}

func matchBucketOptions(excludeBuckets, includeBuckets []string, srcSuffix string) bool {
	if strings.HasPrefix(srcSuffix, "/") {
		srcSuffix = srcSuffix[1:]
	} else if runtime.GOOS == "windows" && strings.HasPrefix(srcSuffix, `\`) {
		srcSuffix = srcSuffix[1:]
	}
	var bucketName string
	if runtime.GOOS == "windows" {
		bucketName = strings.Split(srcSuffix, `\`)[0]
	} else {
		bucketName = strings.Split(srcSuffix, "/")[0]
	}
	// mirror all buckets
	if bucketName == "" {
		return false
	}
	for _, pattern := range excludeBuckets {
		if wildcard.Match(pattern, bucketName) {
			return true
		}
	}
	if len(includeBuckets) <= 0 {
		return false
	}
	for _, pattern := range includeBuckets {
		if wildcard.Match(pattern, bucketName) {
			return false
		}
	}
	return true
}

func deltaSourceTarget(ctx context.Context, sourceURL, targetURL string, opts mirrorOptions, URLsCh chan<- URLs) {
	// source and targets are always directories
	sourceSeparator := string(newClientURL(sourceURL).Separator)
	if !strings.HasSuffix(sourceURL, sourceSeparator) {
		sourceURL = sourceURL + sourceSeparator
	}
	targetSeparator := string(newClientURL(targetURL).Separator)
	if !strings.HasSuffix(targetURL, targetSeparator) {
		targetURL = targetURL + targetSeparator
	}

	// Extract alias and expanded URL
	sourceAlias, sourceURL, _ := mustExpandAlias(sourceURL)
	targetAlias, targetURL, _ := mustExpandAlias(targetURL)

	defer close(URLsCh)

	sourceClnt, err := newClientFromAlias(sourceAlias, sourceURL)
	if err != nil {
		URLsCh <- URLs{Error: err.Trace(sourceAlias, sourceURL)}
		return
	}

	targetClnt, err := newClientFromAlias(targetAlias, targetURL)
	if err != nil {
		URLsCh <- URLs{Error: err.Trace(targetAlias, targetURL)}
		return
	}

	// If the passed source URL points to fs, fetch the absolute src path
	// to correctly calculate targetPath
	if sourceAlias == "" {
		tmpSrcURL, e := filepath.Abs(sourceURL)
		if e == nil {
			sourceURL = tmpSrcURL
		}
	}

	// List both source and target, compare and return values through channel.
	for diffMsg := range objectDifference(ctx, sourceClnt, targetClnt, opts.isMetadata) {
		if diffMsg.Error != nil {
			// Send all errors through the channel
			URLsCh <- URLs{Error: diffMsg.Error, ErrorCond: differInUnknown}
			continue
		}

		srcSuffix := strings.TrimPrefix(diffMsg.FirstURL, sourceURL)
		// Skip the source object if it matches the Exclude options provided
		if matchExcludeOptions(opts.excludeOptions, srcSuffix, newClientURL(sourceURL).Type) {
			continue
		}

		// Skip the source bucket if it matches the provided exclude options or does not match the included options
		if matchBucketOptions(opts.excludeBuckets, opts.includeBuckets, srcSuffix) {
			continue
		}

		tgtSuffix := strings.TrimPrefix(diffMsg.SecondURL, targetURL)
		// Skip the target object if it matches the Exclude options provided
		if matchExcludeOptions(opts.excludeOptions, tgtSuffix, newClientURL(targetURL).Type) {
			continue
		}

		// Skip the target bucket if it matches the provided exclude options or does not match the included options
		if matchBucketOptions(opts.excludeBuckets, opts.includeBuckets, tgtSuffix) {
			continue
		}

		if diffMsg.firstContent != nil {
			var found bool
			for _, esc := range opts.excludeStorageClasses {
				if esc == diffMsg.firstContent.StorageClass {
					found = true
					break
				}
			}
			if found {
				continue
			}
		}

		switch diffMsg.Diff {
		case differInNone:
			// No difference, continue.
		case differInType:
			URLsCh <- URLs{Error: errInvalidTarget(diffMsg.SecondURL)}
		case differInSize, differInMetadata, differInAASourceMTime:
			if !opts.isOverwrite && !opts.isFake && !opts.activeActive {
				// Size or time or etag differs but --overwrite not set.
				URLsCh <- URLs{
					Error:     errOverWriteNotAllowed(diffMsg.SecondURL),
					ErrorCond: diffMsg.Diff,
				}
				continue
			}

			sourceSuffix := strings.TrimPrefix(diffMsg.FirstURL, sourceURL)
			// Either available only in source or size differs and force is set
			targetPath := urlJoinPath(targetURL, sourceSuffix)
			sourceContent := diffMsg.firstContent
			targetContent := &ClientContent{URL: *newClientURL(targetPath)}
			URLsCh <- URLs{
				SourceAlias:   sourceAlias,
				SourceContent: sourceContent,
				TargetAlias:   targetAlias,
				TargetContent: targetContent,
			}
		case differInFirst:
			// Only in first, always copy.
			sourceSuffix := strings.TrimPrefix(diffMsg.FirstURL, sourceURL)
			targetPath := urlJoinPath(targetURL, sourceSuffix)
			sourceContent := diffMsg.firstContent
			targetContent := &ClientContent{URL: *newClientURL(targetPath)}
			URLsCh <- URLs{
				SourceAlias:   sourceAlias,
				SourceContent: sourceContent,
				TargetAlias:   targetAlias,
				TargetContent: targetContent,
			}
		case differInSecond:
			if !opts.isRemove && !opts.isFake {
				continue
			}
			URLsCh <- URLs{
				TargetAlias:   targetAlias,
				TargetContent: diffMsg.secondContent,
			}
		default:
			URLsCh <- URLs{
				Error:     errUnrecognizedDiffType(diffMsg.Diff).Trace(diffMsg.FirstURL, diffMsg.SecondURL),
				ErrorCond: diffMsg.Diff,
			}
		}
	}
}

type mirrorOptions struct {
	isFake, isOverwrite, activeActive                                     bool
	isWatch, isRemove, isMetadata                                         bool
	isRetriable                                                           bool
	isSummary                                                             bool
	skipErrors                                                            bool
	excludeOptions, excludeStorageClasses, excludeBuckets, includeBuckets []string
	encKeyDB                                                              map[string][]prefixSSEPair
	md5, disableMultipart                                                 bool
	olderThan, newerThan                                                  string
	storageClass                                                          string
	userMetadata                                                          map[string]string
	checksum                                                              minio.ChecksumType
}

// Prepares urls that need to be copied or removed based on requested options.
func prepareMirrorURLs(ctx context.Context, sourceURL, targetURL string, opts mirrorOptions) <-chan URLs {
	URLsCh := make(chan URLs)
	go deltaSourceTarget(ctx, sourceURL, targetURL, opts, URLsCh)
	return URLsCh
}
