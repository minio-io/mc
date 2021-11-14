// Copyright (c) 2015-2021 MinIO, Inc.
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
)

//
//   * MIRROR ARGS - VALID CASES
//   =========================
//   mirror(d1..., d2) -> []mirror(d1/f, d2/d1/f)

// checkMirrorSyntax(URLs []string)
func checkMirrorSyntax(ctx context.Context, cliCtx *cli.Context, encKeyDB map[string][]prefixSSEPair) (srcURL, tgtURL string) {
	if len(cliCtx.Args()) != 2 {
		cli.ShowCommandHelpAndExit(cliCtx, "mirror", 1) // last argument is exit code.
	}

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
		_, srcContent, err := url2Stat(ctx, srcURL, "", false, encKeyDB, time.Time{})
		if err != nil {
			fatalIf(err.Trace(srcURL), "Unable to stat source `"+srcURL+"`.")
		}

		if !srcContent.Type.IsDir() {
			fatalIf(errInvalidArgument().Trace(srcContent.URL.String(), srcContent.Type.String()), fmt.Sprintf("Source `%s` is not a folder. Only folders are supported by mirror command.", srcURL))
		}

		if srcClient.Type == fileSystem && !filepath.IsAbs(srcURL) {
			var origSrcURL = srcURL
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

// shouldExcludeFileByFilters returns true if name should be excluded from further processing through filter matching.
// Each filter specifies how the name will match it, and depends on its implementation.
// See nameFilter
//
// An empty name is the special case, and we do not filter it and the function always returns false.
// Consult with TestExcludeOptions in difference_test.go to see use cases
func shouldExcludeFileByFilters(filters nameFilterSlice, name string) bool {
	return name != "" && !filters.filter(name)
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

	// List both source and target, compare and return values through channel.
	for diffMsg := range objectDifference(ctx, sourceClnt, targetClnt, sourceURL, targetURL, opts.isMetadata) {
		if diffMsg.Error != nil {
			// Send all errors through the channel
			URLsCh <- URLs{Error: diffMsg.Error, ErrorCond: differInUnknown}
			continue
		}

		srcSuffix := strings.TrimPrefix(diffMsg.FirstURL, sourceURL)
		// Skip the source object if it matches the pattern filters provided
		if shouldExcludeFileByFilters(opts.nameFilters, srcSuffix) {
			continue
		}

		tgtSuffix := strings.TrimPrefix(diffMsg.SecondURL, targetURL)
		// Skip the target object if it matches the pattern filters provided
		if shouldExcludeFileByFilters(opts.nameFilters, tgtSuffix) {
			continue
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
	isFake, isOverwrite, activeActive bool
	isWatch, isRemove, isMetadata     bool
	nameFilters                       []nameFilter
	encKeyDB                          map[string][]prefixSSEPair
	md5, disableMultipart             bool
	olderThan, newerThan              string
	storageClass                      string
	userMetadata                      map[string]string
}

// Prepares urls that need to be copied or removed based on requested options.
func prepareMirrorURLs(ctx context.Context, sourceURL string, targetURL string, opts mirrorOptions) <-chan URLs {
	URLsCh := make(chan URLs)
	go deltaSourceTarget(ctx, sourceURL, targetURL, opts, URLsCh)
	return URLsCh
}
