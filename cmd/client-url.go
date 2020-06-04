/*
 * MinIO Client (C) 2015 MinIO, Inc.
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
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/minio/mc/pkg/probe"
	"github.com/minio/minio/pkg/mimedb"
)

// ClientURL url client url structure
type ClientURL struct {
	Type            ClientURLType
	Scheme          string
	Host            string
	Path            string
	SchemeSeparator string
	Separator       rune
}

// ClientURLType - enum of different url types
type ClientURLType int

// enum types
const (
	objectStorage = iota // MinIO and S3 compatible cloud storage
	fileSystem           // POSIX compatible file systems
)

// Maybe rawurl is of the form scheme:path. (Scheme must be [a-zA-Z][a-zA-Z0-9+-.]*)
// If so, return scheme, path; else return "", rawurl.
func getScheme(rawurl string) (scheme, path string) {
	urlSplits := strings.Split(rawurl, "://")
	if len(urlSplits) == 2 {
		scheme, uri := urlSplits[0], "//"+urlSplits[1]
		// ignore numbers in scheme
		validScheme := regexp.MustCompile("^[a-zA-Z]+$")
		if uri != "" {
			if validScheme.MatchString(scheme) {
				return scheme, uri
			}
		}
	}
	return "", rawurl
}

// Assuming s is of the form [s delimiter s].
// If so, return s, [delimiter]s or return s, s if cutdelimiter == true
// If no delimiter found return s, "".
func splitSpecial(s string, delimiter string, cutdelimiter bool) (string, string) {
	i := strings.Index(s, delimiter)
	if i < 0 {
		// if delimiter not found return as is.
		return s, ""
	}
	// if delimiter should be removed, remove it.
	if cutdelimiter {
		return s[0:i], s[i+len(delimiter):]
	}
	// return split strings with delimiter
	return s[0:i], s[i:]
}

// getHost - extract host from authority string, we do not support ftp style username@ yet.
func getHost(authority string) (host string) {
	i := strings.LastIndex(authority, "@")
	if i >= 0 {
		// TODO support, username@password style userinfo, useful for ftp support.
		return
	}
	return authority
}

// newClientURL returns an abstracted URL for filesystems and object storage.
func newClientURL(urlStr string) *ClientURL {
	scheme, rest := getScheme(urlStr)
	if strings.HasPrefix(rest, "//") {
		// if rest has '//' prefix, skip them
		var authority string
		authority, rest = splitSpecial(rest[2:], "/", false)
		if rest == "" {
			rest = "/"
		}
		host := getHost(authority)
		if host != "" && (scheme == "http" || scheme == "https") {
			return &ClientURL{
				Scheme:          scheme,
				Type:            objectStorage,
				Host:            host,
				Path:            rest,
				SchemeSeparator: "://",
				Separator:       '/',
			}
		}
	}
	return &ClientURL{
		Type:      fileSystem,
		Path:      rest,
		Separator: filepath.Separator,
	}
}

// joinURLs join two input urls and returns a url
func joinURLs(url1, url2 *ClientURL) *ClientURL {
	var url1Path, url2Path string
	url1Path = filepath.ToSlash(url1.Path)
	url2Path = filepath.ToSlash(url2.Path)
	if strings.HasSuffix(url1Path, "/") {
		url1.Path = url1Path + strings.TrimPrefix(url2Path, "/")
	} else {
		url1.Path = url1Path + "/" + strings.TrimPrefix(url2Path, "/")
	}
	return url1
}

// Clone the url into a new object.
func (u ClientURL) Clone() ClientURL {
	return ClientURL{
		Type:            u.Type,
		Scheme:          u.Scheme,
		Host:            u.Host,
		Path:            u.Path,
		SchemeSeparator: u.SchemeSeparator,
		Separator:       u.Separator,
	}
}

// String convert URL into its canonical form.
func (u ClientURL) String() string {
	var buf bytes.Buffer
	// if fileSystem no translation needed, return as is.
	if u.Type == fileSystem {
		return u.Path
	}
	// if objectStorage convert from any non standard paths to a supported URL path style.
	if u.Type == objectStorage {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
		buf.WriteString("//")
		if h := u.Host; h != "" {
			buf.WriteString(h)
		}
		switch runtime.GOOS {
		case "windows":
			if u.Path != "" && u.Path[0] != '\\' && u.Host != "" && u.Path[0] != '/' {
				buf.WriteByte('/')
			}
			buf.WriteString(strings.Replace(u.Path, "\\", "/", -1))
		default:
			if u.Path != "" && u.Path[0] != '/' && u.Host != "" {
				buf.WriteByte('/')
			}
			buf.WriteString(u.Path)
		}
	}
	return buf.String()
}

// urlJoinPath Join a path to existing URL.
func urlJoinPath(url1, url2 string) string {
	u1 := newClientURL(url1)
	u2 := newClientURL(url2)
	return joinURLs(u1, u2).String()
}

// url2Stat returns stat info for URL.
func url2Stat(ctx context.Context, urlStr string, fileAttr bool, encKeyDB map[string][]prefixSSEPair) (client Client, content *ClientContent, err *probe.Error) {
	client, err = newClient(urlStr)
	if err != nil {
		return nil, nil, err.Trace(urlStr)
	}
	alias, _ := url2Alias(urlStr)
	sse := getSSE(urlStr, encKeyDB[alias])

	content, err = client.Stat(ctx, false, fileAttr, sse)
	if err != nil {
		return nil, nil, err.Trace(urlStr)
	}
	return client, content, nil
}

// url2Alias separates alias and path from the URL. Aliased URL is of
// the form alias/path/to/blah.
func url2Alias(aliasedURL string) (alias, path string) {
	// Save aliased url.
	urlStr := aliasedURL

	// Convert '/' on windows to filepath.Separator.
	urlStr = filepath.FromSlash(urlStr)

	if runtime.GOOS == "windows" {
		// Remove '/' prefix before alias if any to support '\\home' alias
		// style under Windows
		urlStr = strings.TrimPrefix(urlStr, string(filepath.Separator))
	}

	// Remove everything after alias (i.e. after '/').
	urlParts := strings.SplitN(urlStr, string(filepath.Separator), 2)
	if len(urlParts) == 2 {
		// Convert windows style path separator to Unix style.
		return urlParts[0], urlParts[1]
	}
	return urlParts[0], ""
}

// isURLPrefixExists - check if object key prefix exists.
func isURLPrefixExists(urlPrefix string, incomplete bool) bool {
	clnt, err := newClient(urlPrefix)
	if err != nil {
		return false
	}
	isRecursive := false
	isIncomplete := incomplete
	isFetchMeta := false
	for entry := range clnt.List(globalContext, isRecursive, isIncomplete, isFetchMeta, DirNone) {
		return entry.Err == nil
	}
	return false
}

// guessURLContentType - guess content-type of the URL.
// on failure just return 'application/octet-stream'.
func guessURLContentType(urlStr string) string {
	url := newClientURL(urlStr)
	contentType := mimedb.TypeByExtension(filepath.Ext(url.Path))
	return contentType
}
