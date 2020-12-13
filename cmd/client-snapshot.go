/*
 * MinIO Client (C) 2020 MinIO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this fs except in compliance with the License.
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
	"io"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/minio/mc/pkg/probe"
	minio "github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"github.com/minio/minio-go/v7/pkg/replication"
)

type snapClient struct {
	PathURL *ClientURL

	dec      *snapshotDeserializer
	snapName string
	s3Target Client
}

// newSnapClient - instantiate a new snapshot generic Client
func newSnapClient(snapName, clientURL string) (Client, *probe.Error) {
	snapName = strings.TrimPrefix(snapName, snapshotPrefix)
	if snapName == "-" {
		return newSnapClientReader(snapName, clientURL, os.Stdin)
	}
	f, err := openSnapshotFile(snapName)
	if err != nil {
		return nil, err
	}
	return newSnapClientReader(snapName, clientURL, f)
}

// newSnapClientReader - instantiate a new snapshot from a reader.
func newSnapClientReader(snapName, snapAliasedURL string, in io.Reader) (Client, *probe.Error) {
	r, err := newSnapShotReader(in)
	if err != nil {
		return nil, err
	}

	tgt, err := r.ReadTarget()
	if err != nil {
		return nil, err
	}

	hostCfg := aliasConfigV10(*tgt)

	snapTargetPath := strings.TrimPrefix(snapAliasedURL, snapName)
	s3TargetURL, e := url.Parse(tgt.URL)
	if e != nil {
		return nil, probe.NewError(e)
	}

	s3TargetURL.Path = path.Join(s3TargetURL.Path, snapTargetPath)

	s3Config := NewS3Config(s3TargetURL.String(), &hostCfg)
	clnt, err := S3New(s3Config)
	if err != nil {
		return nil, err
	}

	pu := newClientURL(normalizePath(snapAliasedURL))
	if pu.Separator != '/' {
		pu.Path = strings.ReplaceAll(pu.Path, "/", string(pu.Separator))
	}
	return &snapClient{
		PathURL:  pu,
		snapName: snapName,
		s3Target: clnt,
		dec:      r,
	}, nil
}

// URL get url.
func (s *snapClient) GetURL() ClientURL {
	return *s.PathURL
}

// Select replies a stream of query results.
func (s *snapClient) Select(ctx context.Context, expression string, sse encrypt.ServerSide, opts SelectObjectOpts) (io.ReadCloser, *probe.Error) {
	return nil, probe.NewError(APINotImplemented{
		API:     "Select",
		APIType: "snapshot",
	})
}

func (s *snapClient) Watch(ctx context.Context, options WatchOptions) (*WatchObject, *probe.Error) {
	return nil, probe.NewError(APINotImplemented{
		API:     "Watch",
		APIType: "snapshot",
	})
}

// Gets bucket info
func (s *snapClient) GetBucketInfo(ctx context.Context) (BucketInfo, *probe.Error) {
	bucket, _ := s.url2BucketAndObject()
	if bucket == "" {
		return BucketInfo{}, probe.NewError(BucketNameEmpty{})
	}

	for {
		b, err := s.dec.ReadBucket()
		if err != nil {
			return BucketInfo{}, err
		}
		if b == nil {
			break
		}

		if b.Name == bucket {
			url := s.PathURL.Clone()
			url.Path = path.Join(s.snapName, b.Name)
			return BucketInfo{URL: url, Key: b.Name, Size: 0, Type: os.ModeDir}, nil
		}

		err = s.dec.SkipBucketEntries()
		if err != nil {
			return BucketInfo{}, err
		}
	}

	return BucketInfo{}, probe.NewError(BucketDoesNotExist{})
}

/// Object operations.

func (s *snapClient) Put(ctx context.Context, reader io.Reader, size int64, metadata map[string]string, progress io.Reader, sse encrypt.ServerSide, md5, disableMultipart, isPreserve bool) (int64, *probe.Error) {
	return 0, probe.NewError(APINotImplemented{
		API:     "Put",
		APIType: "snapshot",
	})
}

func (s *snapClient) ShareDownload(ctx context.Context, versionID string, expires time.Duration) (string, *probe.Error) {
	return "", probe.NewError(APINotImplemented{
		API:     "ShareDownload",
		APIType: "snapshot",
	})
}

func (s *snapClient) ShareUpload(ctx context.Context, startsWith bool, expires time.Duration, contentType string) (string, map[string]string, *probe.Error) {
	return "", nil, probe.NewError(APINotImplemented{
		API:     "ShareUpload",
		APIType: "snapshot",
	})
}

// Copy - copy data from source to destination
func (s *snapClient) Copy(ctx context.Context, source string, opts CopyOptions, progress io.Reader) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "Copy",
		APIType: "snapshot",
	})
}

// Get returns reader and any additional metadata.
func (s *snapClient) Get(ctx context.Context, opts GetOptions) (io.ReadCloser, *probe.Error) {
	return s.s3Target.Get(ctx, opts)
}

// Remove - remove entry read from clientContent channel.
func (s *snapClient) Remove(ctx context.Context, isIncomplete, isRemoveBucket, isBypass bool, contentCh <-chan *ClientContent) <-chan *probe.Error {
	errorCh := make(chan *probe.Error, 1)
	defer close(errorCh)
	errorCh <- probe.NewError(APINotImplemented{
		API:     "Remove",
		APIType: "snapshot",
	})
	return errorCh
}

func (s *snapClient) Snapshot(ctx context.Context, timeRef time.Time) <-chan *ClientContent {
	contentCh := make(chan *ClientContent, 1)
	contentCh <- &ClientContent{Err: probe.NewError(APINotImplemented{
		API:     "Snapshot",
		APIType: "snapshot",
	})}
	close(contentCh)
	return contentCh
}

// url2BucketAndObject gives bucketName and objectName from URL path.
func (s *snapClient) url2BucketAndObject() (bucketName, objectName string) {
	p := s.PathURL.Path
	tokens := splitStr(p, string(s.PathURL.Separator), 3)
	// Snapshots have '/' as separator.
	prefix := tokens[2]
	if s.PathURL.Separator != '/' {
		prefix = strings.Map(func(r rune) rune {
			if r == s.PathURL.Separator {
				return '/'
			}
			return r
		}, prefix)
	}
	return tokens[1], prefix
}

func (s *snapClient) List(ctx context.Context, opts ListOptions) <-chan *ClientContent {
	contentCh := make(chan *ClientContent)
	go s.list(ctx, contentCh, opts.Recursive, false, false, opts.ShowDir)
	return contentCh
}

// getBucketContents returns bucket content.
// The deserializer must be queued up for bucket contents.
func (s *snapClient) getBucketContents(ctx context.Context, bucket SnapshotBucket, contentCh chan *ClientContent, filter func(*SnapshotEntry) filterAction) {
	entries := make(chan SnapshotEntry, 10000)
	doneCh := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for entry := range entries {
			select {
			case <-ctx.Done():
				contentCh <- &ClientContent{Err: probe.NewError(ctx.Err())}
				return
			default:
			}
			var action filterAction
			if filter != nil {
				action = filter(&entry)
				if action == filterSkipEntry {
					continue
				}
			}
			u := s.PathURL.Clone()
			u.Path = path.Join(s.snapName, bucket.Name, entry.Key)

			var mod os.FileMode
			if entry.Key == "" || strings.HasSuffix(entry.Key, "/") {
				mod |= os.ModeDir
			}

			c := &ClientContent{
				URL:            u,
				Type:           mod,
				VersionID:      entry.VersionID,
				Size:           entry.Size,
				Time:           entry.ModTime,
				ETag:           entry.ETag,
				StorageClass:   entry.StorageClass,
				IsDeleteMarker: entry.IsDeleteMarker,
				IsLatest:       entry.IsLatest,
			}
			contentCh <- c

			if action == filterAbort {
				close(doneCh)
				break
			}
		}
	}()

	err := s.dec.BucketEntries(ctx, entries, doneCh)
	wg.Wait()
	if err != nil {
		contentCh <- &ClientContent{Err: err}
		return
	}
}

func (s *snapClient) listBuckets(ctx context.Context, contentCh chan *ClientContent, isRecursive, _, _ bool, showDir DirOpt) {
	if !isRecursive {
		// List all buckets, but no content.
		for {
			b, err := s.dec.ReadBucket()
			if err != nil {
				contentCh <- &ClientContent{Err: err}
				return
			}
			if b == nil {
				return
			}
			url := s.PathURL.Clone()
			url.Path = path.Join(s.snapName, b.Name)

			c := &ClientContent{
				URL:  url,
				Type: os.ModeDir,
			}

			contentCh <- c
			err = s.dec.SkipBucketEntries()
			if err != nil {
				contentCh <- &ClientContent{Err: err}
				return
			}
		}
	}

	filter := func(entry *SnapshotEntry) filterAction {
		if entry.IsDeleteMarker {
			return filterSkipEntry
		}
		return filterNoAction
	}

	for {
		b, err := s.dec.ReadBucket()
		if err != nil {
			contentCh <- &ClientContent{Err: err}
			return
		}
		if b == nil {
			return
		}
		s.getBucketContents(ctx, *b, contentCh, filter)
	}
}

// List - list files and folders.
// FIXME: showDir appears to be unused
func (s *snapClient) list(ctx context.Context, contentCh chan *ClientContent, isRecursive, _, _ bool, showDir DirOpt) {
	defer close(contentCh)

	bucket, prefix := s.url2BucketAndObject()
	if bucket == "" {
		s.listBuckets(ctx, contentCh, isRecursive, false, false, showDir)
		return
	}

	var lastKey string

	filter := func(entry *SnapshotEntry) filterAction {
		if !strings.HasPrefix(entry.Key, prefix) {
			return filterSkipEntry
		}
		if entry.IsDeleteMarker {
			return filterSkipEntry
		}
		if !isRecursive {
			tmpKey := strings.TrimPrefix(entry.Key, prefix)
			idx := strings.Index(tmpKey, "/")
			if idx > 0 {
				entry.Key = entry.Key[:len(prefix)+idx+1]
			}
			if entry.Key == lastKey {
				return filterSkipEntry
			}
			lastKey = entry.Key
		}
		return filterNoAction
	}
	b, err := s.dec.FindBucket(bucket)
	if err != nil {
		contentCh <- &ClientContent{Err: err}
		return
	}
	if b == nil {
		contentCh <- &ClientContent{Err: probe.NewError(BucketDoesNotExist{Bucket: bucket})}
		return
	}
	s.getBucketContents(ctx, *b, contentCh, filter)
}

// MakeBucket - create a new bucket.
func (s *snapClient) MakeBucket(ctx context.Context, region string, ignoreExisting, withLock bool) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "MakeBucket",
		APIType: "snapshot",
	})
}

// Set object lock configuration of bucket.
func (s *snapClient) SetObjectLockConfig(ctx context.Context, mode minio.RetentionMode, validity uint64, unit minio.ValidityUnit) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetObjectLockConfig",
		APIType: "snapshot",
	})
}

// Get object lock configuration of bucket.
func (s *snapClient) GetObjectLockConfig(ctx context.Context) (status string, mode minio.RetentionMode, validity uint64, unit minio.ValidityUnit, err *probe.Error) {
	return "", "", 0, "", probe.NewError(APINotImplemented{
		API:     "GetObjectLockConfig",
		APIType: "snapshot",
	})
}

// GetAccessRules - unsupported API
func (s *snapClient) GetAccessRules(ctx context.Context) (map[string]string, *probe.Error) {
	return map[string]string{}, probe.NewError(APINotImplemented{
		API:     "GetBucketPolicy",
		APIType: "snapshot",
	})
}

// Set object retention for a given object.
func (s *snapClient) PutObjectRetention(ctx context.Context, versionID string, mode minio.RetentionMode, retainUntilDate time.Time, bypassGovernance bool) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "PutObjectRetention",
		APIType: "snapshot",
	})
}

// Set object legal hold for a given object.
func (s *snapClient) PutObjectLegalHold(ctx context.Context, versionID string, lhold minio.LegalHoldStatus) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "PutObjectLegalHold",
		APIType: "snapshot",
	})
}

// GetAccess - get access policy permissions.
func (s *snapClient) GetAccess(ctx context.Context) (access string, policyJSON string, err *probe.Error) {
	return "", "", probe.NewError(APINotImplemented{
		API:     "GetAccess",
		APIType: "snapshot",
	})

}

// SetAccess - set access policy permissions.
func (s *snapClient) SetAccess(ctx context.Context, access string, isJSON bool) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetAccess",
		APIType: "snapshot",
	})
}

type filterAction int

const (
	filterNoAction filterAction = iota
	filterSkipEntry
	filterAbort
)

func (s *snapClient) statBucket(ctx context.Context, bucket string) (content *ClientContent, err *probe.Error) {
	b, err := s.dec.FindBucket(bucket)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, probe.NewError(BucketDoesNotExist{Bucket: bucket})
	}

	u := s.PathURL.Clone()
	u.Path = path.Join("/", b.Name)

	return &ClientContent{
		URL:  u,
		Type: os.ModeDir,
		Err:  nil,
	}, nil
}

// Stat - get metadata from path.
func (s *snapClient) Stat(ctx context.Context, _ StatOptions) (content *ClientContent, err *probe.Error) {
	bucket, object := s.url2BucketAndObject()

	if bucket == "" {
		return nil, probe.NewError(BucketNameEmpty{})
	}

	if object == "" {
		return s.statBucket(ctx, bucket)
	}

	b, err := s.dec.FindBucket(bucket)
	if err != nil {
		return nil, err
	}
	if b == nil {
		return nil, probe.NewError(BucketDoesNotExist{Bucket: bucket})
	}

	object = strings.TrimSuffix(object, "/")

	// filter helps navigate all objects entries in a specific bucket
	// until it finds the specific object that we want to Stat()
	filter := func(entry *SnapshotEntry) filterAction {
		if entry.IsDeleteMarker {
			return filterSkipEntry
		}
		if strings.HasPrefix(entry.Key, object+"/") {
			*entry = SnapshotEntry{Key: object + "/"}
			return filterAbort
		}
		if entry.Key != object {
			return filterSkipEntry
		}
		return filterAbort
	}

	contentCh := make(chan *ClientContent, 2)
	s.getBucketContents(ctx, *b, contentCh, filter)
	close(contentCh)

	content = <-contentCh
	if content == nil {
		return nil, probe.NewError(ObjectMissing{})
	}

	if content.Err != nil {
		return nil, content.Err
	}

	return content, nil
}

func (s *snapClient) AddUserAgent(_, _ string) {
}

// Get Object Tags
func (s *snapClient) GetTags(ctx context.Context, _ string) (map[string]string, *probe.Error) {
	return nil, probe.NewError(APINotImplemented{
		API:     "GetObjectTagging",
		APIType: "snapshot",
	})
}

// Set Object tags
func (s *snapClient) SetTags(ctx context.Context, versionID, tags string) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetObjectTagging",
		APIType: "snapshot",
	})
}

// Delete object tags
func (s *snapClient) DeleteTags(ctx context.Context, versionID string) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "DeleteObjectTagging",
		APIType: "snapshot",
	})
}

// Get lifecycle configuration for a given bucket, not implemented.
func (s *snapClient) GetLifecycle(ctx context.Context) (*lifecycle.Configuration, *probe.Error) {
	return nil, probe.NewError(APINotImplemented{
		API:     "GetLifecycle",
		APIType: "snapshot",
	})
}

// Set lifecycle configuration for a given bucket, not implemented.
func (s *snapClient) SetLifecycle(ctx context.Context, config *lifecycle.Configuration) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetLifecycle",
		APIType: "snapshot",
	})
}

// Versioning operations

// Not implemeneted
func (s *snapClient) GetVersioning(ctx context.Context) (minio.BucketVersioningConfiguration, *probe.Error) {
	return minio.BucketVersioningConfiguration{}, probe.NewError(APINotImplemented{
		API:     "GetVersioning",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) SetVersioning(ctx context.Context, status string) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetVersioning",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) GetReplication(ctx context.Context) (replication.Config, *probe.Error) {
	return replication.Config{}, probe.NewError(APINotImplemented{
		API:     "GetReplication",
		APIType: "snapshot",
	})

}

// Not implemented
func (s *snapClient) SetReplication(ctx context.Context, cfg *replication.Config, opts replication.Options) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetReplication",
		APIType: "snapshot",
	})

}

// Not implemented
func (s *snapClient) RemoveReplication(ctx context.Context) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "RemoveReplication",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) GetEncryption(ctx context.Context) (string, string, *probe.Error) {
	return "", "", probe.NewError(APINotImplemented{
		API:     "GetEncryption",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) SetEncryption(ctx context.Context, algorithm, keyID string) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetEncryption",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) DeleteEncryption(ctx context.Context) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "DeleteEncryption",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) GetObjectLegalHold(ctx context.Context, versionID string) (minio.LegalHoldStatus, *probe.Error) {
	return "", probe.NewError(APINotImplemented{
		API:     "GetObjectLegalHold",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) GetObjectRetention(ctx context.Context, versionID string) (minio.RetentionMode, time.Time, *probe.Error) {
	return "", time.Time{}, probe.NewError(APINotImplemented{
		API:     "GetObjectRetention",
		APIType: "snapshot",
	})
}

// Not implemented
func (s *snapClient) GetVersion(ctx context.Context) (minio.BucketVersioningConfiguration, *probe.Error) {
	return minio.BucketVersioningConfiguration{}, probe.NewError(APINotImplemented{
		API:     "GetVersion",
		APIType: "snapshot",
	})
}

// SetVersion - Set version configuration on a bucket, not implemented
func (s *snapClient) SetVersion(ctx context.Context, status string) *probe.Error {
	return probe.NewError(APINotImplemented{
		API:     "SetVersion",
		APIType: "snapshot",
	})
}