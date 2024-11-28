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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/minio/minio-go/v7/pkg/cors"
	"github.com/minio/pkg/v3/env"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	"github.com/minio/minio-go/v7/pkg/notification"
	"github.com/minio/minio-go/v7/pkg/policy"
	"github.com/minio/minio-go/v7/pkg/replication"
	"github.com/minio/minio-go/v7/pkg/s3utils"
	"github.com/minio/minio-go/v7/pkg/sse"
	"github.com/minio/minio-go/v7/pkg/tags"
	"github.com/minio/pkg/v3/mimedb"

	"github.com/minio/mc/pkg/deadlineconn"
	"github.com/minio/mc/pkg/probe"
)

// S3Client construct
type S3Client struct {
	sync.Mutex
	targetURL    *ClientURL
	api          *minio.Client
	virtualStyle bool
}

const (
	amazonHostNameAccelerated = "s3-accelerate.amazonaws.com"
	googleHostName            = "storage.googleapis.com"
	serverEncryptionKeyPrefix = "x-amz-server-side-encryption"

	defaultRecordDelimiter = "\n"
	defaultFieldDelimiter  = ","
)

const (
	recordDelimiterType      = "recorddelimiter"
	fieldDelimiterType       = "fielddelimiter"
	quoteCharacterType       = "quotechar"
	quoteEscapeCharacterType = "quoteescchar"
	quoteFieldsType          = "quotefields"
	fileHeaderType           = "fileheader"
	commentCharType          = "commentchar"
	typeJSONType             = "type"
	// AmzObjectLockMode sets object lock mode
	AmzObjectLockMode = "X-Amz-Object-Lock-Mode"
	// AmzObjectLockRetainUntilDate sets object lock retain until date
	AmzObjectLockRetainUntilDate = "X-Amz-Object-Lock-Retain-Until-Date"
	// AmzObjectLockLegalHold sets object lock legal hold
	AmzObjectLockLegalHold = "X-Amz-Object-Lock-Legal-Hold"
	amzObjectSSEKMSKeyID   = "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id"
	amzObjectSSE           = "X-Amz-Server-Side-Encryption"
)

type dialContext func(ctx context.Context, network, addr string) (net.Conn, error)

// newCustomDialContext setups a custom dialer for any external communication and proxies.
func newCustomDialContext(c *Config) dialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 15 * time.Second,
		}

		if ip, ok := globalResolvers[addr]; ok {
			if _, port, err := net.SplitHostPort(addr); err == nil {
				addr = net.JoinHostPort(ip.String(), port)
			} else {
				addr = ip.String()
			}
		}

		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		dconn := deadlineconn.New(conn).
			WithReadDeadline(c.ConnReadDeadline).
			WithWriteDeadline(c.ConnWriteDeadline)

		return dconn, nil
	}
}

// newCustomDialTLSContext setups a custom TLS dialer for any external communication and proxies.
func newCustomDialTLSContext(tlsConf *tls.Config) dialContext {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 15 * time.Second,
			},
			Config: tlsConf,
		}

		if ip, ok := globalResolvers[addr]; ok {
			dialer.Config = dialer.Config.Clone()
			if host, port, err := net.SplitHostPort(addr); err == nil {
				dialer.Config.ServerName = host // Set SNI
				addr = net.JoinHostPort(ip.String(), port)
			} else {
				dialer.Config.ServerName = addr // Set SNI
				addr = ip.String()
			}
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

var timeSentinel = time.Unix(0, 0).UTC()

// getConfigHash returns the Hash for che *Config
func getConfigHash(config *Config) uint32 {
	// Creates a parsed URL.
	targetURL := newClientURL(config.HostURL)

	// Save if target supports virtual host style.
	hostName := targetURL.Host

	// Generate a hash out of s3Conf.
	confHash := fnv.New32a()
	confHash.Write([]byte(hostName + config.AccessKey + config.SecretKey + config.SessionToken))
	confSum := confHash.Sum32()
	return confSum
}

// isHostTLS returns true if the Host URL is https
func isHostTLS(config *Config) bool {
	// By default enable HTTPs.
	useTLS := true
	targetURL := newClientURL(config.HostURL)
	if targetURL.Scheme == "http" {
		useTLS = false
	}
	return useTLS
}

type notifyExpiringTLS struct {
	transport http.RoundTripper
}

var globalExpiringCerts sync.Map

func (n notifyExpiringTLS) RoundTrip(req *http.Request) (res *http.Response, err error) {
	if n.transport == nil {
		return nil, errors.New("invalid transport")
	}

	res, err = n.transport.RoundTrip(req)
	if err != nil || res.TLS == nil || len(res.TLS.PeerCertificates) == 0 {
		return res, err
	}

	cert := res.TLS.PeerCertificates[0] // leaf certificate
	validityDur := cert.NotAfter.Sub(cert.NotBefore)
	// Warn if less than 10% of time left and it is less than 28 days.
	if time.Until(cert.NotAfter) < time.Duration(min(0.1*float64(validityDur), 28*24*float64(time.Hour))) {
		globalExpiringCerts.Store(req.Host, cert.NotAfter)
	}

	return res, err
}

// useTrailingHeaders will enable trailing headers on S3 clients.
var useTrailingHeaders atomic.Bool

// newFactory encloses New function with client cache.
func newFactory() func(config *Config) (Client, *probe.Error) {
	clientCache := make(map[uint32]*minio.Client)
	var mutex sync.Mutex

	// Return New function.
	return func(config *Config) (Client, *probe.Error) {
		// Creates a parsed URL.
		targetURL := newClientURL(config.HostURL)

		// Save if target supports virtual host style.
		hostName := targetURL.Host

		confSum := getConfigHash(config)

		useTLS := isHostTLS(config)

		// Instantiate s3
		s3Clnt := &S3Client{}
		// Save the target URL.
		s3Clnt.targetURL = targetURL

		s3Clnt.virtualStyle = isVirtualHostStyle(hostName, config.Lookup)
		isS3AcceleratedEndpoint := isAmazonAccelerated(hostName)

		if s3Clnt.virtualStyle {
			// If Google URL replace it with 'storage.googleapis.com'
			if isGoogle(hostName) {
				hostName = googleHostName
			}
		}

		// Lookup previous cache by hash.
		mutex.Lock()
		defer mutex.Unlock()
		var api *minio.Client
		var found bool
		if api, found = clientCache[confSum]; !found {

			transport := config.getTransport()

			credsChain, err := config.getCredsChain()
			if err != nil {
				return nil, err
			}

			var e error

			options := minio.Options{
				Creds:           credentials.NewChainCredentials(credsChain),
				Secure:          useTLS,
				Region:          env.Get("MC_REGION", env.Get("AWS_REGION", "")),
				BucketLookup:    config.Lookup,
				Transport:       transport,
				TrailingHeaders: useTrailingHeaders.Load(),
			}

			api, e = minio.New(hostName, &options)
			if e != nil {
				return nil, probe.NewError(e)
			}

			// If Amazon Accelerated URL is requested enable it.
			if isS3AcceleratedEndpoint {
				api.SetS3TransferAccelerate(amazonHostNameAccelerated)
			}

			// Set app info.
			api.SetAppInfo(config.AppName, config.AppVersion)

			// Cache the new MinIO Client with hash of config as key.
			clientCache[confSum] = api
		}

		// Store the new api object.
		s3Clnt.api = api

		return s3Clnt, nil
	}
}

// S3New returns an initialized S3Client structure. If debug is enabled,
// it also enables an internal trace transport.
var S3New = newFactory()

// GetURL get url.
func (c *S3Client) GetURL() ClientURL {
	return c.targetURL.Clone()
}

// AddNotificationConfig - Add bucket notification
func (c *S3Client) AddNotificationConfig(ctx context.Context, arn string, events []string, prefix, suffix string, ignoreExisting bool) *probe.Error {
	bucket, _ := c.url2BucketAndObject()

	accountArn, err := notification.NewArnFromString(arn)
	if err != nil {
		return probe.NewError(invalidArgumentErr(err)).Untrace()
	}
	nc := notification.NewConfig(accountArn)

	// Get any enabled notification.
	mb, e := c.api.GetBucketNotification(ctx, bucket)
	if e != nil {
		return probe.NewError(e)
	}

	// Configure events
	for _, event := range events {
		switch event {
		case "put":
			nc.AddEvents(notification.ObjectCreatedAll)
		case "delete":
			nc.AddEvents(notification.ObjectRemovedAll)
		case "get":
			nc.AddEvents(notification.ObjectAccessedAll)
		case "replica":
			nc.AddEvents(notification.EventType("s3:Replication:*"))
		case "ilm":
			nc.AddEvents(notification.EventType("s3:ObjectRestore:*"), notification.ObjectTransitionAll, notification.ILMDelMarkerExpirationDelete)
		case "scanner":
			nc.AddEvents(notification.EventType("s3:Scanner:ManyVersions"))
			nc.AddEvents(notification.EventType("s3:Scanner:BigPrefix"))
		default:
			return errInvalidArgument().Trace(events...)
		}
	}
	if prefix != "" {
		nc.AddFilterPrefix(prefix)
	}
	if suffix != "" {
		nc.AddFilterSuffix(suffix)
	}

	switch accountArn.Service {
	case "sns":
		if !mb.AddTopic(nc) {
			return errInvalidArgument().Trace("Overlapping Topic configs")
		}
	case "sqs":
		if !mb.AddQueue(nc) {
			return errInvalidArgument().Trace("Overlapping Queue configs")
		}
	case "lambda":
		if !mb.AddLambda(nc) {
			return errInvalidArgument().Trace("Overlapping lambda configs")
		}
	default:
		return errInvalidArgument().Trace(accountArn.Service)
	}

	// Set the new bucket configuration
	if err := c.api.SetBucketNotification(ctx, bucket, mb); err != nil {
		if ignoreExisting && strings.Contains(err.Error(), "An object key name filtering rule defined with overlapping prefixes, overlapping suffixes, or overlapping combinations of prefixes and suffixes for the same event types") {
			return nil
		}
		return probe.NewError(err)
	}
	return nil
}

// RemoveNotificationConfig - Remove bucket notification
func (c *S3Client) RemoveNotificationConfig(ctx context.Context, arn, event, prefix, suffix string) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	// Remove all notification configs if arn is empty
	if arn == "" {
		if err := c.api.RemoveAllBucketNotification(ctx, bucket); err != nil {
			return probe.NewError(err)
		}
		return nil
	}

	mb, e := c.api.GetBucketNotification(ctx, bucket)
	if e != nil {
		return probe.NewError(e)
	}

	accountArn, err := notification.NewArnFromString(arn)
	if err != nil {
		return probe.NewError(invalidArgumentErr(err)).Untrace()
	}

	// if we are passed filters for either events, suffix or prefix, then only delete the single event that matches
	// the arguments
	if event != "" || suffix != "" || prefix != "" {
		// Translate events to type events for comparison
		events := strings.Split(event, ",")
		var eventsTyped []notification.EventType
		for _, e := range events {
			switch e {
			case "put":
				eventsTyped = append(eventsTyped, notification.ObjectCreatedAll)
			case "delete":
				eventsTyped = append(eventsTyped, notification.ObjectRemovedAll)
			case "get":
				eventsTyped = append(eventsTyped, notification.ObjectAccessedAll)
			case "replica":
				eventsTyped = append(eventsTyped, notification.EventType("s3:Replication:*"))
			case "ilm":
				eventsTyped = append(eventsTyped, notification.EventType("s3:ObjectRestore:*"))
				eventsTyped = append(eventsTyped, notification.EventType("s3:ObjectTransition:*"))
			case "scanner":
				eventsTyped = append(eventsTyped, notification.EventType("s3:Scanner:ManyVersions"))
				eventsTyped = append(eventsTyped, notification.EventType("s3:Scanner:BigPrefix"))
			default:
				return errInvalidArgument().Trace(events...)
			}
		}
		var err error
		// based on the arn type, we'll look for the event in the corresponding sublist and delete it if there's a match
		switch accountArn.Service {
		case "sns":
			err = mb.RemoveTopicByArnEventsPrefixSuffix(accountArn, eventsTyped, prefix, suffix)
		case "sqs":
			err = mb.RemoveQueueByArnEventsPrefixSuffix(accountArn, eventsTyped, prefix, suffix)
		case "lambda":
			err = mb.RemoveLambdaByArnEventsPrefixSuffix(accountArn, eventsTyped, prefix, suffix)
		default:
			return errInvalidArgument().Trace(accountArn.Service)
		}
		if err != nil {
			return probe.NewError(err)
		}

	} else {
		// remove all events for matching arn
		switch accountArn.Service {
		case "sns":
			mb.RemoveTopicByArn(accountArn)
		case "sqs":
			mb.RemoveQueueByArn(accountArn)
		case "lambda":
			mb.RemoveLambdaByArn(accountArn)
		default:
			return errInvalidArgument().Trace(accountArn.Service)
		}
	}

	// Set the new bucket configuration
	if e := c.api.SetBucketNotification(ctx, bucket, mb); e != nil {
		return probe.NewError(e)
	}
	return nil
}

// NotificationConfig notification config
type NotificationConfig struct {
	ID     string   `json:"id"`
	Arn    string   `json:"arn"`
	Events []string `json:"events"`
	Prefix string   `json:"prefix"`
	Suffix string   `json:"suffix"`
}

// ListNotificationConfigs - List notification configs
func (c *S3Client) ListNotificationConfigs(ctx context.Context, arn string) ([]NotificationConfig, *probe.Error) {
	var configs []NotificationConfig
	bucket, _ := c.url2BucketAndObject()
	mb, e := c.api.GetBucketNotification(ctx, bucket)
	if e != nil {
		return nil, probe.NewError(e)
	}

	// Generate pretty event names from event types
	prettyEventNames := func(eventsTypes []notification.EventType) []string {
		var result []string
		for _, eventType := range eventsTypes {
			result = append(result, string(eventType))
		}
		return result
	}

	getFilters := func(config notification.Config) (prefix, suffix string) {
		if config.Filter == nil {
			return
		}
		for _, filter := range config.Filter.S3Key.FilterRules {
			if strings.ToLower(filter.Name) == "prefix" {
				prefix = filter.Value
			}
			if strings.ToLower(filter.Name) == "suffix" {
				suffix = filter.Value
			}

		}
		return prefix, suffix
	}

	for _, config := range mb.TopicConfigs {
		if arn != "" && config.Topic != arn {
			continue
		}
		prefix, suffix := getFilters(config.Config)
		configs = append(configs, NotificationConfig{
			ID:     config.ID,
			Arn:    config.Topic,
			Events: prettyEventNames(config.Events),
			Prefix: prefix,
			Suffix: suffix,
		})
	}

	for _, config := range mb.QueueConfigs {
		if arn != "" && config.Queue != arn {
			continue
		}
		prefix, suffix := getFilters(config.Config)
		configs = append(configs, NotificationConfig{
			ID:     config.ID,
			Arn:    config.Queue,
			Events: prettyEventNames(config.Events),
			Prefix: prefix,
			Suffix: suffix,
		})
	}

	for _, config := range mb.LambdaConfigs {
		if arn != "" && config.Lambda != arn {
			continue
		}
		prefix, suffix := getFilters(config.Config)
		configs = append(configs, NotificationConfig{
			ID:     config.ID,
			Arn:    config.Lambda,
			Events: prettyEventNames(config.Events),
			Prefix: prefix,
			Suffix: suffix,
		})
	}

	return configs, nil
}

// Supported content types
var supportedContentTypes = []string{
	"csv",
	"json",
	"gzip",
	"bzip2",
}

// set the SelectObjectOutputSerialization struct using options passed in by client. If unspecified,
// default S3 API specified defaults
func selectObjectOutputOpts(selOpts SelectObjectOpts, i minio.SelectObjectInputSerialization) minio.SelectObjectOutputSerialization {
	var isOK bool
	var recDelim, fldDelim, quoteChar, quoteEscChar, qf string

	o := minio.SelectObjectOutputSerialization{}
	if _, ok := selOpts.OutputSerOpts["json"]; ok {
		jo := minio.JSONOutputOptions{}
		if recDelim, isOK = selOpts.OutputSerOpts["json"][recordDelimiterType]; !isOK {
			recDelim = "\n"
		}
		jo.SetRecordDelimiter(recDelim)
		o.JSON = &jo
	}
	if _, ok := selOpts.OutputSerOpts["csv"]; ok {
		ocsv := minio.CSVOutputOptions{}
		if recDelim, isOK = selOpts.OutputSerOpts["csv"][recordDelimiterType]; !isOK {
			recDelim = defaultRecordDelimiter
		}
		ocsv.SetRecordDelimiter(recDelim)
		if fldDelim, isOK = selOpts.OutputSerOpts["csv"][fieldDelimiterType]; !isOK {
			fldDelim = defaultFieldDelimiter
		}
		ocsv.SetFieldDelimiter(fldDelim)
		if quoteChar, isOK = selOpts.OutputSerOpts["csv"][quoteCharacterType]; isOK {
			ocsv.SetQuoteCharacter(quoteChar)
		}
		if quoteEscChar, isOK = selOpts.OutputSerOpts["csv"][quoteEscapeCharacterType]; isOK {
			ocsv.SetQuoteEscapeCharacter(quoteEscChar)
		}
		if qf, isOK = selOpts.OutputSerOpts["csv"][quoteFieldsType]; isOK {
			ocsv.SetQuoteFields(minio.CSVQuoteFields(qf))
		}
		o.CSV = &ocsv
	}
	// default to CSV output if options left unspecified
	if o.CSV == nil && o.JSON == nil {
		if i.JSON != nil {
			j := minio.JSONOutputOptions{}
			j.SetRecordDelimiter("\n")
			o.JSON = &j
		} else {
			ocsv := minio.CSVOutputOptions{}
			ocsv.SetRecordDelimiter(defaultRecordDelimiter)
			ocsv.SetFieldDelimiter(defaultFieldDelimiter)
			o.CSV = &ocsv
		}
	}
	return o
}

func trimCompressionFileExts(name string) string {
	return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, ".gz"), ".bz"), ".bz2")
}

// set the SelectObjectInputSerialization struct using options passed in by client. If unspecified,
// default S3 API specified defaults
func selectObjectInputOpts(selOpts SelectObjectOpts, object string) minio.SelectObjectInputSerialization {
	var isOK bool
	var recDelim, fldDelim, quoteChar, quoteEscChar, fileHeader, commentChar, typ string

	i := minio.SelectObjectInputSerialization{}
	if _, ok := selOpts.InputSerOpts["parquet"]; ok {
		iparquet := minio.ParquetInputOptions{}
		i.Parquet = &iparquet
	}
	if _, ok := selOpts.InputSerOpts["json"]; ok {
		j := minio.JSONInputOptions{}
		if typ = selOpts.InputSerOpts["json"][typeJSONType]; typ != "" {
			j.SetType(minio.JSONType(typ))
		}
		i.JSON = &j
	}
	if _, ok := selOpts.InputSerOpts["csv"]; ok {
		icsv := minio.CSVInputOptions{}
		icsv.SetRecordDelimiter(defaultRecordDelimiter)
		if recDelim, isOK = selOpts.InputSerOpts["csv"][recordDelimiterType]; isOK {
			icsv.SetRecordDelimiter(recDelim)
		}
		if fldDelim, isOK = selOpts.InputSerOpts["csv"][fieldDelimiterType]; isOK {
			icsv.SetFieldDelimiter(fldDelim)
		}
		if quoteChar, isOK = selOpts.InputSerOpts["csv"][quoteCharacterType]; isOK {
			icsv.SetQuoteCharacter(quoteChar)
		}
		if quoteEscChar, isOK = selOpts.InputSerOpts["csv"][quoteEscapeCharacterType]; isOK {
			icsv.SetQuoteEscapeCharacter(quoteEscChar)
		}
		if fileHeader, isOK = selOpts.InputSerOpts["csv"][fileHeaderType]; isOK {
			icsv.SetFileHeaderInfo(minio.CSVFileHeaderInfo(fileHeader))
		}
		if commentChar, isOK = selOpts.InputSerOpts["csv"][commentCharType]; isOK {
			icsv.SetComments(commentChar)
		}
		i.CSV = &icsv
	}
	if i.CSV == nil && i.JSON == nil && i.Parquet == nil {
		ext := filepath.Ext(trimCompressionFileExts(object))
		if strings.Contains(ext, "csv") {
			icsv := minio.CSVInputOptions{}
			icsv.SetRecordDelimiter(defaultRecordDelimiter)
			icsv.SetFieldDelimiter(defaultFieldDelimiter)
			icsv.SetFileHeaderInfo(minio.CSVFileHeaderInfoUse)
			i.CSV = &icsv
		}
		if strings.Contains(ext, "parquet") || strings.Contains(object, ".parquet") {
			iparquet := minio.ParquetInputOptions{}
			i.Parquet = &iparquet
		}
		if strings.Contains(ext, "json") {
			ijson := minio.JSONInputOptions{}
			ijson.SetType(minio.JSONLinesType)
			i.JSON = &ijson
		}
	}
	if i.CompressionType == "" {
		i.CompressionType = selectCompressionType(selOpts, object)
	}
	return i
}

// get client specified compression type or default compression type from file extension
func selectCompressionType(selOpts SelectObjectOpts, object string) minio.SelectCompressionType {
	ext := filepath.Ext(object)
	contentType := mimedb.TypeByExtension(ext)

	if selOpts.CompressionType != "" {
		return selOpts.CompressionType
	}
	if strings.Contains(ext, "parquet") || strings.Contains(object, ".parquet") {
		return minio.SelectCompressionNONE
	}
	if contentType != "" {
		if strings.Contains(contentType, "gzip") {
			return minio.SelectCompressionGZIP
		} else if strings.Contains(contentType, "bzip") {
			return minio.SelectCompressionBZIP
		}
	}
	return minio.SelectCompressionNONE
}

// Select - select object content wrapper.
func (c *S3Client) Select(ctx context.Context, expression string, sse encrypt.ServerSide, selOpts SelectObjectOpts) (io.ReadCloser, *probe.Error) {
	opts := minio.SelectObjectOptions{
		Expression:     expression,
		ExpressionType: minio.QueryExpressionTypeSQL,
		// Set any encryption headers
		ServerSideEncryption: sse,
	}

	bucket, object := c.url2BucketAndObject()

	opts.InputSerialization = selectObjectInputOpts(selOpts, object)
	opts.OutputSerialization = selectObjectOutputOpts(selOpts, opts.InputSerialization)
	reader, e := c.api.SelectObjectContent(ctx, bucket, object, opts)
	if e != nil {
		return nil, probe.NewError(e)
	}
	return reader, nil
}

func (c *S3Client) notificationToEventsInfo(ninfo notification.Info) []EventInfo {
	eventsInfo := make([]EventInfo, len(ninfo.Records))
	for i, record := range ninfo.Records {
		bucketName := record.S3.Bucket.Name
		var key string
		// Unescape only if needed, look for URL encoded content.
		if strings.Contains(record.S3.Object.Key, "%2F") {
			var e error
			key, e = url.QueryUnescape(record.S3.Object.Key)
			if e != nil {
				key = record.S3.Object.Key
			}
		} else {
			key = record.S3.Object.Key
		}
		u := c.targetURL.Clone()
		u.Path = path.Join(string(u.Separator), bucketName, key)
		if strings.HasPrefix(record.EventName, "s3:ObjectCreated:") {
			if strings.HasPrefix(record.EventName, "s3:ObjectCreated:Copy") {
				eventsInfo[i] = EventInfo{
					Time:         record.EventTime,
					Size:         record.S3.Object.Size,
					UserMetadata: record.S3.Object.UserMetadata,
					Path:         u.String(),
					Type:         notification.ObjectCreatedCopy,
					Host:         record.Source.Host,
					Port:         record.Source.Port,
					UserAgent:    record.Source.UserAgent,
				}
			} else if strings.HasPrefix(record.EventName, "s3:ObjectCreated:PutRetention") {
				eventsInfo[i] = EventInfo{
					Time:         record.EventTime,
					Size:         record.S3.Object.Size,
					UserMetadata: record.S3.Object.UserMetadata,
					Path:         u.String(),
					Type:         notification.EventType("s3:ObjectCreated:PutRetention"),
					Host:         record.Source.Host,
					Port:         record.Source.Port,
					UserAgent:    record.Source.UserAgent,
				}
			} else if strings.HasPrefix(record.EventName, "s3:ObjectCreated:PutLegalHold") {
				eventsInfo[i] = EventInfo{
					Time:         record.EventTime,
					Size:         record.S3.Object.Size,
					UserMetadata: record.S3.Object.UserMetadata,
					Path:         u.String(),
					Type:         notification.EventType("s3:ObjectCreated:PutLegalHold"),
					Host:         record.Source.Host,
					Port:         record.Source.Port,
					UserAgent:    record.Source.UserAgent,
				}
			} else {
				eventsInfo[i] = EventInfo{
					Time:         record.EventTime,
					Size:         record.S3.Object.Size,
					UserMetadata: record.S3.Object.UserMetadata,
					Path:         u.String(),
					Type:         notification.ObjectCreatedPut,
					Host:         record.Source.Host,
					Port:         record.Source.Port,
					UserAgent:    record.Source.UserAgent,
				}
			}
		} else {
			eventsInfo[i] = EventInfo{
				Time:         record.EventTime,
				Size:         record.S3.Object.Size,
				UserMetadata: record.S3.Object.UserMetadata,
				Path:         u.String(),
				Type:         notification.EventType(record.EventName),
				Host:         record.Source.Host,
				Port:         record.Source.Port,
				UserAgent:    record.Source.UserAgent,
			}
		}
	}
	return eventsInfo
}

// Watch - Start watching on all bucket events for a given account ID.
func (c *S3Client) Watch(ctx context.Context, options WatchOptions) (*WatchObject, *probe.Error) {
	// Extract bucket and object.
	bucket, object := c.url2BucketAndObject()

	// Validation
	if bucket == "" && object != "" {
		return nil, errInvalidArgument().Trace(bucket, object)
	}
	if object != "" && options.Prefix != "" {
		return nil, errInvalidArgument().Trace(options.Prefix, object)
	}

	// Flag set to set the notification.
	var events []string
	for _, event := range options.Events {
		switch event {
		case "put":
			events = append(events, string(notification.ObjectCreatedAll))
		case "delete":
			events = append(events, string(notification.ObjectRemovedAll))
		case "get":
			events = append(events, string(notification.ObjectAccessedAll))
		case "replica":
			events = append(events, "s3:Replication:*") // TODO: add it to minio-go as constant
		case "ilm":
			events = append(events, "s3:ObjectRestore:*", "s3:ObjectTransition:*") // TODO: add it to minio-go as constant
		case "bucket-creation":
			events = append(events, string(notification.BucketCreatedAll))
		case "bucket-removal":
			events = append(events, string(notification.BucketRemovedAll))
		case "scanner":
			events = append(events, "s3:Scanner:ManyVersions", "s3:Scanner:BigPrefix")
		default:
			return nil, errInvalidArgument().Trace(event)
		}
	}

	wo := &WatchObject{
		EventInfoChan: make(chan []EventInfo),
		ErrorChan:     make(chan *probe.Error),
		DoneChan:      make(chan struct{}),
	}

	listenCtx, listenCancel := context.WithCancel(ctx)

	var eventsCh <-chan notification.Info
	if bucket != "" {
		if object != "" && options.Prefix == "" {
			options.Prefix = object
		}
		eventsCh = c.api.ListenBucketNotification(listenCtx, bucket, options.Prefix, options.Suffix, events)
	} else {
		eventsCh = c.api.ListenNotification(listenCtx, "", "", events)
	}

	go func() {
		defer close(wo.EventInfoChan)
		defer close(wo.ErrorChan)
		defer listenCancel()

		for {
			// Start listening on all bucket events.
			select {
			case notificationInfo, ok := <-eventsCh:
				if !ok {
					return
				}
				if notificationInfo.Err != nil {
					var perr *probe.Error
					if minio.ToErrorResponse(notificationInfo.Err).Code == "NotImplemented" {
						perr = probe.NewError(APINotImplemented{
							API:     "Watch",
							APIType: c.GetURL().String(),
						})
					} else {
						perr = probe.NewError(notificationInfo.Err)
					}
					wo.Errors() <- perr
				} else {
					wo.Events() <- c.notificationToEventsInfo(notificationInfo)
				}
			case <-wo.DoneChan:
				return
			}
		}
	}()

	return wo, nil
}

// Get - get object with GET options.
func (c *S3Client) Get(ctx context.Context, opts GetOptions) (io.ReadCloser, *ClientContent, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	o := minio.GetObjectOptions{
		ServerSideEncryption: opts.SSE,
		VersionID:            opts.VersionID,
		PartNumber:           opts.PartNumber,
	}
	if opts.Zip {
		o.Set("x-minio-extract", "true")
	}
	if opts.RangeStart != 0 {
		err := o.SetRange(opts.RangeStart, 0)
		if err != nil {
			return nil, nil, probe.NewError(err)
		}
	}
	// Disallow automatic decompression for some objects with content-encoding set.
	o.Set("Accept-Encoding", "identity")

	cr := minio.Core{Client: c.api}
	reader, objectInfo, _, e := cr.GetObject(ctx, bucket, object, o)
	if e != nil {
		errResponse := minio.ToErrorResponse(e)
		if errResponse.Code == "NoSuchBucket" {
			return nil, nil, probe.NewError(BucketDoesNotExist{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "InvalidBucketName" {
			return nil, nil, probe.NewError(BucketInvalid{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "NoSuchKey" {
			return nil, nil, probe.NewError(ObjectMissing{})
		}
		return nil, nil, probe.NewError(e)
	}
	return reader, c.objectInfo2ClientContent(bucket, objectInfo), nil
}

// Copy - copy object, uses server side copy API. Also uses an abstracted API
// such that large file sizes will be copied in multipart manner on server
// side.
func (c *S3Client) Copy(ctx context.Context, source string, opts CopyOptions, progress io.Reader) *probe.Error {
	dstBucket, dstObject := c.url2BucketAndObject()
	if dstBucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	metadata := make(map[string]string, len(opts.metadata))
	for k, v := range opts.metadata {
		metadata[k] = v
	}

	delete(metadata, "X-Amz-Storage-Class")
	if opts.storageClass != "" {
		metadata["X-Amz-Storage-Class"] = opts.storageClass
	}

	tokens := splitStr(source, string(c.targetURL.Separator), 3)

	// Source object
	srcOpts := minio.CopySrcOptions{
		Bucket:     tokens[1],
		Object:     tokens[2],
		Encryption: opts.srcSSE,
		VersionID:  opts.versionID,
	}

	destOpts := minio.CopyDestOptions{
		Bucket:     dstBucket,
		Object:     dstObject,
		Encryption: opts.tgtSSE,
		Progress:   progress,
		Size:       opts.size,
	}

	if lockModeStr, ok := metadata[AmzObjectLockMode]; ok {
		destOpts.Mode = minio.RetentionMode(strings.ToUpper(lockModeStr))
		delete(metadata, AmzObjectLockMode)
	}

	if retainUntilDateStr, ok := metadata[AmzObjectLockRetainUntilDate]; ok {
		delete(metadata, AmzObjectLockRetainUntilDate)
		if t, e := time.Parse(time.RFC3339, retainUntilDateStr); e == nil {
			destOpts.RetainUntilDate = t.UTC()
		}
	}

	if lh, ok := metadata[AmzObjectLockLegalHold]; ok {
		destOpts.LegalHold = minio.LegalHoldStatus(lh)
		delete(metadata, AmzObjectLockLegalHold)
	}

	// Assign metadata after irrelevant parts are delete above
	destOpts.UserMetadata = metadata
	destOpts.ReplaceMetadata = len(metadata) > 0

	var e error
	if opts.disableMultipart || opts.size < 64*1024*1024 {
		_, e = c.api.CopyObject(ctx, destOpts, srcOpts)
	} else {
		_, e = c.api.ComposeObject(ctx, destOpts, srcOpts)
	}

	if e != nil {
		errResponse := minio.ToErrorResponse(e)
		if errResponse.Code == "AccessDenied" {
			return probe.NewError(PathInsufficientPermission{
				Path: c.targetURL.String(),
			})
		}
		if errResponse.Code == "NoSuchBucket" {
			return probe.NewError(BucketDoesNotExist{
				Bucket: dstBucket,
			})
		}
		if errResponse.Code == "InvalidBucketName" {
			return probe.NewError(BucketInvalid{
				Bucket: dstBucket,
			})
		}
		if errResponse.Code == "NoSuchKey" {
			return probe.NewError(ObjectMissing{})
		}
		return probe.NewError(e)
	}
	return nil
}

// Put - upload an object with custom metadata.
func (c *S3Client) Put(ctx context.Context, reader io.Reader, size int64, progress io.Reader, putOpts PutOptions) (int64, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return 0, probe.NewError(BucketNameEmpty{})
	}

	metadata := make(map[string]string, len(putOpts.metadata))
	for k, v := range putOpts.metadata {
		metadata[k] = v
	}

	// Do not copy storage class, it needs to be specified in putOpts
	delete(metadata, "X-Amz-Storage-Class")

	contentType, ok := metadata["Content-Type"]
	if ok {
		delete(metadata, "Content-Type")
	} else {
		// Set content-type if not specified.
		contentType = "application/octet-stream"
	}

	cacheControl, ok := metadata["Cache-Control"]
	if ok {
		delete(metadata, "Cache-Control")
	}

	contentEncoding, ok := metadata["Content-Encoding"]
	if ok {
		delete(metadata, "Content-Encoding")
	}

	contentDisposition, ok := metadata["Content-Disposition"]
	if ok {
		delete(metadata, "Content-Disposition")
	}

	contentLanguage, ok := metadata["Content-Language"]
	if ok {
		delete(metadata, "Content-Language")
	}

	var tagsMap map[string]string
	tagsHdr, ok := metadata["X-Amz-Tagging"]
	if ok {
		tagsSet, e := tags.Parse(tagsHdr, true)
		if e != nil {
			return 0, probe.NewError(e)
		}
		tagsMap = tagsSet.ToMap()
		delete(metadata, "X-Amz-Tagging")
	}

	lockModeStr, ok := metadata[AmzObjectLockMode]
	lockMode := minio.RetentionMode("")
	if ok {
		lockMode = minio.RetentionMode(strings.ToUpper(lockModeStr))
		delete(metadata, AmzObjectLockMode)
	}

	retainUntilDate := timeSentinel
	retainUntilDateStr, ok := metadata[AmzObjectLockRetainUntilDate]
	if ok {
		delete(metadata, AmzObjectLockRetainUntilDate)
		if t, e := time.Parse(time.RFC3339, retainUntilDateStr); e == nil {
			retainUntilDate = t.UTC()
		}
	}

	opts := minio.PutObjectOptions{
		UserMetadata:          metadata,
		UserTags:              tagsMap,
		Progress:              progress,
		ContentType:           contentType,
		CacheControl:          cacheControl,
		ContentDisposition:    contentDisposition,
		ContentEncoding:       contentEncoding,
		ContentLanguage:       contentLanguage,
		StorageClass:          strings.ToUpper(putOpts.storageClass),
		ServerSideEncryption:  putOpts.sse,
		SendContentMd5:        putOpts.md5,
		Checksum:              putOpts.checksum,
		DisableMultipart:      putOpts.disableMultipart,
		PartSize:              putOpts.multipartSize,
		NumThreads:            putOpts.multipartThreads,
		ConcurrentStreamParts: putOpts.concurrentStream, // if enabled honors NumThreads for piped() uploads
	}

	if !retainUntilDate.IsZero() && !retainUntilDate.Equal(timeSentinel) {
		opts.RetainUntilDate = retainUntilDate
	}

	if lockModeStr != "" {
		opts.Mode = lockMode
		opts.SendContentMd5 = true
	}

	if lh, ok := metadata[AmzObjectLockLegalHold]; ok {
		delete(metadata, AmzObjectLockLegalHold)
		opts.LegalHold = minio.LegalHoldStatus(strings.ToUpper(lh))
		opts.SendContentMd5 = true
	}

	if putOpts.ifNotExists {
		// Only supported in newer MinIO releases.
		opts.SetMatchETagExcept("*")
	}

	ui, e := c.api.PutObject(ctx, bucket, object, reader, size, opts)
	if e != nil {
		errResponse := minio.ToErrorResponse(e)
		if errResponse.Code == "UnexpectedEOF" || e == io.EOF {
			return ui.Size, probe.NewError(UnexpectedEOF{
				TotalSize:    size,
				TotalWritten: ui.Size,
			})
		}
		if errResponse.Code == "AccessDenied" {
			return ui.Size, probe.NewError(PathInsufficientPermission{
				Path: c.targetURL.String(),
			})
		}
		if errResponse.Code == "MethodNotAllowed" {
			return ui.Size, probe.NewError(ObjectAlreadyExists{
				Object: object,
			})
		}
		if errResponse.Code == "XMinioObjectExistsAsDirectory" {
			return ui.Size, probe.NewError(ObjectAlreadyExistsAsDirectory{
				Object: object,
			})
		}
		if errResponse.Code == "NoSuchBucket" {
			return ui.Size, probe.NewError(BucketDoesNotExist{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "InvalidBucketName" {
			return ui.Size, probe.NewError(BucketInvalid{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "NoSuchKey" {
			return ui.Size, probe.NewError(ObjectMissing{})
		}
		return ui.Size, probe.NewError(e)
	}
	return ui.Size, nil
}

// PutPart - upload an object with custom metadata. (Same as Put)
func (c *S3Client) PutPart(ctx context.Context, reader io.Reader, size int64, progress io.Reader, putOpts PutOptions) (int64, *probe.Error) {
	return c.Put(ctx, reader, size, progress, putOpts)
}

// Remove incomplete uploads.
func (c *S3Client) removeIncompleteObjects(ctx context.Context, bucket string, objectsCh <-chan minio.ObjectInfo) <-chan minio.RemoveObjectResult {
	removeObjectErrorCh := make(chan minio.RemoveObjectResult)

	// Goroutine reads from objectsCh and sends error to removeObjectErrorCh if any.
	go func() {
		defer close(removeObjectErrorCh)

		for info := range objectsCh {
			if err := c.api.RemoveIncompleteUpload(ctx, bucket, info.Key); err != nil {
				removeObjectErrorCh <- minio.RemoveObjectResult{ObjectName: info.Key, Err: err}
			}
		}
	}()

	return removeObjectErrorCh
}

// AddUserAgent - add custom user agent.
func (c *S3Client) AddUserAgent(app, version string) {
	c.api.SetAppInfo(app, version)
}

// RemoveResult returns the error or result of the removed objects.
type RemoveResult struct {
	minio.RemoveObjectResult
	BucketName string
	Err        *probe.Error
}

// Remove - remove object or bucket(s).
func (c *S3Client) Remove(ctx context.Context, isIncomplete, isRemoveBucket, isBypass, isForceDel bool, contentCh <-chan *ClientContent) <-chan RemoveResult {
	resultCh := make(chan RemoveResult)

	prevBucket := ""
	// Maintain objectsCh, statusCh for each bucket
	var objectsCh chan minio.ObjectInfo
	var statusCh <-chan minio.RemoveObjectResult
	opts := minio.RemoveObjectsOptions{
		GovernanceBypass: isBypass,
	}

	go func() {
		defer close(resultCh)

		if isForceDel {
			bucket, object := c.url2BucketAndObject()
			if e := c.api.RemoveObject(ctx, bucket, object, minio.RemoveObjectOptions{
				ForceDelete: isForceDel,
			}); e != nil {
				resultCh <- RemoveResult{
					Err: probe.NewError(e),
				}
				return
			}
			resultCh <- RemoveResult{
				BucketName: bucket,
				RemoveObjectResult: minio.RemoveObjectResult{
					ObjectName: object,
				},
			}
			return
		}

		_, object := c.url2BucketAndObject()
		if isRemoveBucket && object != "" {
			resultCh <- RemoveResult{
				Err: probe.NewError(errors.New(
					"use `mc rm` command to delete prefixes, or point your" +
						" bucket directly, `mc rb <alias>/<bucket-name>/`"),
				),
			}
			return
		}

		for {
			select {
			case <-ctx.Done():
				resultCh <- RemoveResult{
					Err: probe.NewError(ctx.Err()),
				}
				return
			case content, ok := <-contentCh:
				if !ok {
					goto breakout
				}

				// Convert content.URL.Path to objectName for objectsCh.
				bucket, objectName := c.splitPath(content.URL.Path)
				objectVersionID := content.VersionID

				// We don't treat path when bucket is
				// empty, just skip it when it happens.
				if bucket == "" {
					continue
				}

				// Init objectsCh the first time.
				if prevBucket == "" {
					objectsCh = make(chan minio.ObjectInfo)
					prevBucket = bucket
					if isIncomplete {
						statusCh = c.removeIncompleteObjects(ctx, bucket, objectsCh)
					} else {
						statusCh = c.api.RemoveObjectsWithResult(ctx, bucket, objectsCh, opts)
					}
				}

				if prevBucket != bucket {
					if objectsCh != nil {
						close(objectsCh)
					}

					for removeStatus := range statusCh {
						if removeStatus.Err != nil {
							resultCh <- RemoveResult{
								BucketName: bucket,
								Err:        probe.NewError(removeStatus.Err),
							}
						} else {
							resultCh <- RemoveResult{
								BucketName:         bucket,
								RemoveObjectResult: removeStatus,
							}
						}
					}

					// Remove bucket if it qualifies.
					if isRemoveBucket && !isIncomplete {
						if e := c.api.RemoveBucket(ctx, prevBucket); e != nil {
							resultCh <- RemoveResult{
								BucketName: bucket,
								Err:        probe.NewError(e),
							}
							return
						}
					}
					// Re-init objectsCh for next bucket
					objectsCh = make(chan minio.ObjectInfo)
					if isIncomplete {
						statusCh = c.removeIncompleteObjects(ctx, bucket, objectsCh)
					} else {
						statusCh = c.api.RemoveObjectsWithResult(ctx, bucket, objectsCh, opts)
					}
					prevBucket = bucket
				}

				if objectName != "" {
					// Send object name once but continuously checks for pending
					// errors in parallel, the reason is that minio-go RemoveObjects
					// can block if there is any pending error not received yet.
					sent := false
					for !sent {
						select {
						case objectsCh <- minio.ObjectInfo{
							Key:       objectName,
							VersionID: objectVersionID,
						}:
							sent = true
						case removeStatus := <-statusCh:
							if removeStatus.Err != nil {
								resultCh <- RemoveResult{
									BucketName: bucket,
									Err:        probe.NewError(removeStatus.Err),
								}
							} else {
								resultCh <- RemoveResult{
									BucketName:         bucket,
									RemoveObjectResult: removeStatus,
								}
							}
						}
					}
				} else {
					// end of bucket - close the objectsCh
					if objectsCh != nil {
						close(objectsCh)
					}
					objectsCh = nil
				}
			}
		}

	breakout:
		// Close objectsCh at end of contentCh
		if objectsCh != nil {
			close(objectsCh)
		}
		// Write remove objects status to resultCh
		if statusCh != nil {
			for removeStatus := range statusCh {
				if removeStatus.Err != nil {
					removeStatus.Err = errors.New(strings.Replace(
						removeStatus.Err.Error(), "Object is WORM protected",
						"Object, '"+removeStatus.ObjectName+" (Version ID="+
							removeStatus.ObjectVersionID+")' is WORM protected", 1))

					// If the removeStatus error message is:
					// "Object is WORM protected and cannot be overwritten",
					// it is too generic. We have the object's name and vid.
					// Adding the object's name and version id into the error msg
					resultCh <- RemoveResult{
						Err: probe.NewError(removeStatus.Err),
					}
				} else {
					resultCh <- RemoveResult{
						BucketName:         prevBucket,
						RemoveObjectResult: removeStatus,
					}
				}
			}
		}
		// Remove last bucket if it qualifies.
		if isRemoveBucket && prevBucket != "" && !isIncomplete {
			if e := c.api.RemoveBucket(ctx, prevBucket); e != nil {
				resultCh <- RemoveResult{
					BucketName: prevBucket,
					Err:        probe.NewError(e),
				}
				return
			}
		}
	}()
	return resultCh
}

// MakeBucket - make a new bucket.
func (c *S3Client) MakeBucket(ctx context.Context, region string, ignoreExisting, withLock bool) *probe.Error {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	if object != "" {
		if !strings.HasSuffix(object, string(c.targetURL.Separator)) {
			object += string(c.targetURL.Separator)
		}
		var retried bool
		for {
			_, e := c.api.PutObject(ctx, bucket, object, bytes.NewReader([]byte("")), 0,
				// Always send Content-MD5 to succeed with bucket with
				// locking enabled. There is no performance hit since
				// this is always an empty object
				minio.PutObjectOptions{SendContentMd5: true},
			)
			if e == nil {
				return nil
			}
			if retried {
				return probe.NewError(e)
			}
			switch minio.ToErrorResponse(e).Code {
			case "NoSuchBucket":
				opts := minio.MakeBucketOptions{Region: region, ObjectLocking: withLock}
				if e = c.api.MakeBucket(ctx, bucket, opts); e != nil {
					return probe.NewError(e)
				}
				retried = true
				continue
			}
			return probe.NewError(e)
		}
	}

	var e error
	opts := minio.MakeBucketOptions{Region: region, ObjectLocking: withLock}
	if e = c.api.MakeBucket(ctx, bucket, opts); e != nil {
		// Ignore bucket already existing error when ignoreExisting flag is enabled
		if ignoreExisting {
			switch minio.ToErrorResponse(e).Code {
			case "BucketAlreadyOwnedByYou":
				fallthrough
			case "BucketAlreadyExists":
				return nil
			}
		}
		return probe.NewError(e)
	}
	return nil
}

// RemoveBucket removes a bucket, forcibly if asked
func (c *S3Client) RemoveBucket(ctx context.Context, forceRemove bool) *probe.Error {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	if object != "" {
		return probe.NewError(BucketInvalid{c.joinPath(bucket, object)})
	}

	opts := minio.RemoveBucketOptions{ForceDelete: forceRemove}
	if e := c.api.RemoveBucketWithOptions(ctx, bucket, opts); e != nil {
		return probe.NewError(e)
	}
	return nil
}

// GetAccessRules - get configured policies from the server
func (c *S3Client) GetAccessRules(ctx context.Context) (map[string]string, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return map[string]string{}, probe.NewError(BucketNameEmpty{})
	}
	policies := map[string]string{}
	policyStr, e := c.api.GetBucketPolicy(ctx, bucket)
	if e != nil {
		return nil, probe.NewError(e)
	}
	if policyStr == "" {
		return policies, nil
	}
	var p policy.BucketAccessPolicy
	if e = json.Unmarshal([]byte(policyStr), &p); e != nil {
		return nil, probe.NewError(e)
	}
	policyRules := policy.GetPolicies(p.Statements, bucket, object)
	// Hide policy data structure at this level
	for k, v := range policyRules {
		policies[k] = string(v)
	}
	return policies, nil
}

// GetAccess get access policy permissions.
func (c *S3Client) GetAccess(ctx context.Context) (string, string, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return "", "", probe.NewError(BucketNameEmpty{})
	}
	policyStr, e := c.api.GetBucketPolicy(ctx, bucket)
	if e != nil {
		return "", "", probe.NewError(e)
	}
	if policyStr == "" {
		return string(policy.BucketPolicyNone), policyStr, nil
	}
	var p policy.BucketAccessPolicy
	if e = json.Unmarshal([]byte(policyStr), &p); e != nil {
		return "", "", probe.NewError(e)
	}
	pType := string(policy.GetPolicy(p.Statements, bucket, object))
	if pType == string(policy.BucketPolicyNone) && policyStr != "" {
		pType = "custom"
	}
	return pType, policyStr, nil
}

// SetAccess set access policy permissions.
func (c *S3Client) SetAccess(ctx context.Context, bucketPolicy string, isJSON bool) *probe.Error {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	if isJSON {
		if e := c.api.SetBucketPolicy(ctx, bucket, bucketPolicy); e != nil {
			return probe.NewError(e)
		}
		return nil
	}
	policyStr, e := c.api.GetBucketPolicy(ctx, bucket)
	if e != nil {
		return probe.NewError(e)
	}
	p := policy.BucketAccessPolicy{Version: "2012-10-17"}
	if policyStr != "" {
		if e = json.Unmarshal([]byte(policyStr), &p); e != nil {
			return probe.NewError(e)
		}
	}
	p.Statements = policy.SetPolicy(p.Statements, policy.BucketPolicy(bucketPolicy), bucket, object)
	if len(p.Statements) == 0 {
		if e = c.api.SetBucketPolicy(ctx, bucket, ""); e != nil {
			return probe.NewError(e)
		}
		return nil
	}
	policyB, e := json.Marshal(p)
	if e != nil {
		return probe.NewError(e)
	}
	if e = c.api.SetBucketPolicy(ctx, bucket, string(policyB)); e != nil {
		return probe.NewError(e)
	}
	return nil
}

// listObjectWrapper - select ObjectList mode depending on arguments
func (c *S3Client) listObjectWrapper(ctx context.Context, bucket, object string, isRecursive bool, timeRef time.Time, withVersions, withDeleteMarkers, metadata bool, maxKeys int, zip bool) <-chan minio.ObjectInfo {
	if !timeRef.IsZero() || withVersions {
		return c.listVersions(ctx, bucket, object, ListOptions{Recursive: isRecursive, TimeRef: timeRef, WithOlderVersions: withVersions, WithDeleteMarkers: withDeleteMarkers})
	}

	if isGoogle(c.targetURL.Host) {
		// Google Cloud S3 layer doesn't implement ListObjectsV2 implementation
		// https://github.com/minio/mc/issues/3073
		return c.api.ListObjects(ctx, bucket, minio.ListObjectsOptions{Prefix: object, Recursive: isRecursive, UseV1: true, MaxKeys: maxKeys})
	}
	opts := minio.ListObjectsOptions{Prefix: object, Recursive: isRecursive, WithMetadata: metadata, MaxKeys: maxKeys}
	if zip {
		// If prefix ends with .zip, add a slash.
		if strings.HasSuffix(object, ".zip") {
			opts.Prefix = object + "/"
		}
		opts.Set("x-minio-extract", "true")
	}
	return c.api.ListObjects(ctx, bucket, opts)
}

func (c *S3Client) statIncompleteUpload(ctx context.Context, bucket, object string) (*ClientContent, *probe.Error) {
	nonRecursive := false
	objectMetadata := &ClientContent{}
	// Prefix to pass to minio-go listing in order to fetch a given object/directory
	prefix := strings.TrimRight(object, string(c.targetURL.Separator))

	for objectMultipartInfo := range c.api.ListIncompleteUploads(ctx, bucket, prefix, nonRecursive) {
		if objectMultipartInfo.Err != nil {
			return nil, probe.NewError(objectMultipartInfo.Err)
		}

		if objectMultipartInfo.Key == object {
			objectMetadata.BucketName = bucket
			objectMetadata.URL = c.targetURL.Clone()
			objectMetadata.Time = objectMultipartInfo.Initiated
			objectMetadata.Size = objectMultipartInfo.Size
			objectMetadata.Type = os.FileMode(0o664)
			objectMetadata.Metadata = map[string]string{}
			return objectMetadata, nil
		}

		if strings.HasSuffix(objectMultipartInfo.Key, string(c.targetURL.Separator)) {
			objectMetadata.BucketName = bucket
			objectMetadata.URL = c.targetURL.Clone()
			objectMetadata.Type = os.ModeDir
			objectMetadata.Metadata = map[string]string{}
			return objectMetadata, nil
		}
	}
	return nil, probe.NewError(ObjectMissing{})
}

// Stat - send a 'HEAD' on a bucket or object to fetch its metadata. It also returns
// a DIR type content if a prefix does exist in the server.
func (c *S3Client) Stat(ctx context.Context, opts StatOptions) (*ClientContent, *probe.Error) {
	c.Lock()
	defer c.Unlock()
	bucket, path := c.url2BucketAndObject()

	// Bucket name cannot be empty, stat on URL has no meaning.
	if bucket == "" {
		url := c.targetURL.Clone()
		url.Path = string(c.targetURL.Separator)
		return &ClientContent{
			URL:        url,
			Size:       0,
			Type:       os.ModeDir,
			BucketName: bucket,
		}, nil
	}

	if path == "" {
		content, err := c.bucketStat(ctx, BucketStatOptions{
			bucket:             bucket,
			ignoreBucketExists: opts.ignoreBucketExists,
		})
		if err != nil {
			return nil, err.Trace(bucket)
		}
		return content, nil
	}

	// If the request is for incomplete upload stat, handle it here.
	if opts.incomplete {
		return c.statIncompleteUpload(ctx, bucket, path)
	}

	// The following code tries to calculate if a given prefix/object does really exist
	// using minio-go listing API. The following inputs are supported:
	//     - /path/to/existing/object
	//     - /path/to/existing_directory
	//     - /path/to/existing_directory/
	//     - /path/to/directory_marker
	//     - /path/to/directory_marker/

	// Start with a HEAD request first to return object metadata information.
	// If the object is not found, continue to look for a directory marker or a prefix
	if !strings.HasSuffix(path, string(c.targetURL.Separator)) && opts.timeRef.IsZero() {
		o := minio.StatObjectOptions{ServerSideEncryption: opts.sse, VersionID: opts.versionID}
		if opts.isZip {
			o.Set("x-minio-extract", "true")
		}

		o.Set("x-amz-checksum-mode", "ENABLED")
		ctnt, err := c.getObjectStat(ctx, bucket, path, o)
		if err == nil {
			return ctnt, nil
		}

		// Ignore object missing error but return for other errors
		if !errors.As(err.ToGoError(), &ObjectMissing{}) && !errors.As(err.ToGoError(), &ObjectIsDeleteMarker{}) {
			return nil, err
		}

		// when versionID is specified we do not have to perform List() operation
		// when headOnly is specified we do not have to perform List() operation
		if (opts.versionID != "" || opts.headOnly) && errors.As(err.ToGoError(), &ObjectMissing{}) || errors.As(err.ToGoError(), &ObjectIsDeleteMarker{}) {
			return nil, probe.NewError(ObjectMissing{opts.timeRef})
		}

		// The object is not found, look for a directory marker or a prefix
		path += string(c.targetURL.Separator)
	}

	nonRecursive := false
	maxKeys := 1
	for objectStat := range c.listObjectWrapper(ctx, bucket, path, nonRecursive, opts.timeRef,
		opts.includeVersions, opts.includeVersions, false, maxKeys, opts.isZip) {
		if objectStat.Err != nil {
			return nil, probe.NewError(objectStat.Err)
		}
		// In case of a directory marker
		if path == objectStat.Key {
			return c.objectInfo2ClientContent(bucket, objectStat), nil
		}
		if strings.HasPrefix(objectStat.Key, path) {
			// An object inside the prefix is found, then the prefix exists.
			return c.prefixInfo2ClientContent(bucket, path), nil
		}
	}

	return nil, probe.NewError(ObjectMissing{opts.timeRef})
}

// getObjectStat returns the metadata of an object from a HEAD call.
func (c *S3Client) getObjectStat(ctx context.Context, bucket, object string, opts minio.StatObjectOptions) (*ClientContent, *probe.Error) {
	objectStat, e := c.api.StatObject(ctx, bucket, object, opts)
	objectMetadata := c.objectInfo2ClientContent(bucket, objectStat)
	if e != nil {
		errResponse := minio.ToErrorResponse(e)
		if errResponse.Code == "AccessDenied" {
			return nil, probe.NewError(PathInsufficientPermission{Path: c.targetURL.String()})
		}
		if errResponse.Code == "NoSuchBucket" {
			return nil, probe.NewError(BucketDoesNotExist{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "InvalidBucketName" {
			return nil, probe.NewError(BucketInvalid{
				Bucket: bucket,
			})
		}
		if errResponse.Code == "NoSuchKey" {
			if objectMetadata.IsDeleteMarker {
				return nil, probe.NewError(ObjectIsDeleteMarker{})
			}
			return nil, probe.NewError(ObjectMissing{})
		}
		return nil, probe.NewError(e)
	}
	// HEAD with a version ID will not return version in the response headers
	if objectMetadata.VersionID == "" {
		objectMetadata.VersionID = opts.VersionID
	}
	return objectMetadata, nil
}

func isAmazon(host string) bool {
	return s3utils.IsAmazonEndpoint(url.URL{Host: host})
}

func isAmazonChina(host string) bool {
	amazonS3ChinaHost := regexp.MustCompile(`^s3\.(cn.*?)\.amazonaws\.com\.cn$`)
	parts := amazonS3ChinaHost.FindStringSubmatch(host)
	return len(parts) > 1
}

func isAmazonAccelerated(host string) bool {
	return host == "s3-accelerate.amazonaws.com"
}

func isGoogle(host string) bool {
	return s3utils.IsGoogleEndpoint(url.URL{Host: host})
}

// Figure out if the URL is of 'virtual host' style.
// Use lookup from config to see if dns/path style look
// up should be used. If it is set to "auto", use virtual
// style for supported hosts such as Amazon S3 and Google
// Cloud Storage. Otherwise, default to path style
func isVirtualHostStyle(host string, lookup minio.BucketLookupType) bool {
	if lookup == minio.BucketLookupDNS {
		return true
	}
	if lookup == minio.BucketLookupPath {
		return false
	}
	return isAmazon(host) && !isAmazonChina(host) || isGoogle(host) || isAmazonAccelerated(host)
}

func url2BucketAndObject(u *ClientURL) (bucketName, objectName string) {
	tokens := splitStr(u.Path, string(u.Separator), 3)
	return tokens[1], tokens[2]
}

// url2BucketAndObject gives bucketName and objectName from URL path.
func (c *S3Client) url2BucketAndObject() (bucketName, objectName string) {
	return url2BucketAndObject(c.targetURL)
}

// splitPath split path into bucket and object.
func (c *S3Client) splitPath(path string) (bucketName, objectName string) {
	path = strings.TrimPrefix(path, string(c.targetURL.Separator))

	// Handle path if its virtual style.
	if c.virtualStyle {
		hostIndex := strings.Index(c.targetURL.Host, "s3")
		if hostIndex == -1 {
			hostIndex = strings.Index(c.targetURL.Host, "s3-accelerate")
		}
		if hostIndex == -1 {
			hostIndex = strings.Index(c.targetURL.Host, "storage.googleapis")
		}
		if hostIndex > 0 {
			bucketName = c.targetURL.Host[:hostIndex-1]
			objectName = path
			return bucketName, objectName
		}
	}

	tokens := splitStr(path, string(c.targetURL.Separator), 2)
	return tokens[0], tokens[1]
}

/// Bucket API operations.

func (c *S3Client) listVersions(ctx context.Context, b, o string, opts ListOptions) chan minio.ObjectInfo {
	objectInfoCh := make(chan minio.ObjectInfo)
	go func() {
		defer close(objectInfoCh)
		c.listVersionsRoutine(ctx, b, o, opts, objectInfoCh)
	}()
	return objectInfoCh
}

func (c *S3Client) listVersionsRoutine(ctx context.Context, b, o string, opts ListOptions, objectInfoCh chan minio.ObjectInfo) {
	var buckets []string
	if b == "" {
		bucketsInfo, err := c.api.ListBuckets(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case objectInfoCh <- minio.ObjectInfo{
				Err: err,
			}:
			}
			return
		}
		for _, b := range bucketsInfo {
			buckets = append(buckets, b.Name)
		}
	} else {
		buckets = append(buckets, b)
	}

	for _, b := range buckets {
		var skipKey string
		for objectVersion := range c.api.ListObjects(ctx, b, minio.ListObjectsOptions{
			Prefix:       o,
			Recursive:    opts.Recursive,
			WithVersions: true,
			WithMetadata: opts.WithMetadata,
		}) {
			if objectVersion.Err != nil {
				select {
				case <-ctx.Done():
					return
				case objectInfoCh <- objectVersion:
				}
				continue
			}

			if !opts.WithOlderVersions && skipKey == objectVersion.Key {
				// Skip current version if not asked to list all versions
				// and we already listed the current object key name
				continue
			}

			if opts.TimeRef.IsZero() || objectVersion.LastModified.Before(opts.TimeRef) {
				skipKey = objectVersion.Key

				// Skip if this is a delete marker and we are not asked to list it
				if !opts.WithDeleteMarkers && objectVersion.IsDeleteMarker {
					continue
				}

				select {
				case <-ctx.Done():
					return
				case objectInfoCh <- objectVersion:
				}
			}
		}
	}
}

// ListBuckets - list buckets
func (c *S3Client) ListBuckets(ctx context.Context) ([]*ClientContent, *probe.Error) {
	buckets, err := c.api.ListBuckets(ctx)
	if err != nil {
		return nil, probe.NewError(err)
	}
	bucketsList := make([]*ClientContent, 0, len(buckets))
	for _, b := range buckets {
		bucketsList = append(bucketsList, c.bucketInfo2ClientContent(b))
	}
	return bucketsList, nil
}

// List - list at delimited path, if not recursive.
func (c *S3Client) List(ctx context.Context, opts ListOptions) <-chan *ClientContent {
	c.Lock()
	defer c.Unlock()

	contentCh := make(chan *ClientContent)
	go func() {
		defer close(contentCh)
		if !opts.TimeRef.IsZero() || opts.WithOlderVersions {
			c.versionedList(ctx, contentCh, opts)
		} else {
			c.unversionedList(ctx, contentCh, opts)
		}
	}()

	return contentCh
}

// versionedList returns objects versions if the S3 backend supports versioning,
// it falls back to the regular listing if not.
func (c *S3Client) versionedList(ctx context.Context, contentCh chan *ClientContent, opts ListOptions) {
	b, o := c.url2BucketAndObject()
	switch {
	case b == "" && o == "":
		buckets, err := c.api.ListBuckets(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case contentCh <- &ClientContent{
				Err: probe.NewError(err),
			}:
			}
			return
		}
		if opts.Recursive {
			sortBucketsNameWithSlash(buckets)
		}
		for _, bucket := range buckets {
			if opts.ShowDir != DirLast {
				select {
				case <-ctx.Done():
					return
				case contentCh <- c.bucketInfo2ClientContent(bucket):
				}
			}
			for objectVersion := range c.listVersions(ctx, bucket.Name, "", opts) {
				if objectVersion.Err != nil {
					if minio.ToErrorResponse(objectVersion.Err).Code == "NotImplemented" {
						goto noVersioning
					}
					select {
					case <-ctx.Done():
						return
					case contentCh <- &ClientContent{
						Err: probe.NewError(objectVersion.Err),
					}:
					}
					continue
				}
				select {
				case <-ctx.Done():
					return
				case contentCh <- c.objectInfo2ClientContent(bucket.Name, objectVersion):
				}
			}

			if opts.ShowDir == DirLast {
				select {
				case <-ctx.Done():
					return
				case contentCh <- c.bucketInfo2ClientContent(bucket):
				}
			}
		}
		return
	default:
		for objectVersion := range c.listVersions(ctx, b, o, opts) {
			if objectVersion.Err != nil {
				if minio.ToErrorResponse(objectVersion.Err).Code == "NotImplemented" {
					goto noVersioning
				}
				select {
				case <-ctx.Done():
					return
				case contentCh <- &ClientContent{
					Err: probe.NewError(objectVersion.Err),
				}:
				}
				continue
			}
			select {
			case <-ctx.Done():
				return
			case contentCh <- c.objectInfo2ClientContent(b, objectVersion):
			}
		}
		return
	}

noVersioning:
	c.unversionedList(ctx, contentCh, opts)
}

// unversionedList is the non versioned S3 listing
func (c *S3Client) unversionedList(ctx context.Context, contentCh chan *ClientContent, opts ListOptions) {
	if opts.Incomplete {
		if opts.Recursive {
			c.listIncompleteRecursiveInRoutine(ctx, contentCh, opts)
		} else {
			c.listIncompleteInRoutine(ctx, contentCh)
		}
	} else {
		if opts.Recursive {
			c.listRecursiveInRoutine(ctx, contentCh, opts)
		} else {
			c.listInRoutine(ctx, contentCh, opts)
		}
	}
}

func (c *S3Client) listIncompleteInRoutine(ctx context.Context, contentCh chan *ClientContent) {
	// get bucket and object from URL.
	b, o := c.url2BucketAndObject()
	switch {
	case b == "" && o == "":
		buckets, err := c.api.ListBuckets(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case contentCh <- &ClientContent{
				Err: probe.NewError(err),
			}:
			}
			return
		}
		isRecursive := false
		for _, bucket := range buckets {
			for object := range c.api.ListIncompleteUploads(ctx, bucket.Name, o, isRecursive) {
				if object.Err != nil {
					select {
					case <-ctx.Done():
						return
					case contentCh <- &ClientContent{
						Err: probe.NewError(object.Err),
					}:
					}
					return
				}
				content := &ClientContent{}
				url := c.targetURL.Clone()
				// Join bucket with - incoming object key.
				url.Path = c.buildAbsPath(bucket.Name, object.Key)
				switch {
				case strings.HasSuffix(object.Key, string(c.targetURL.Separator)):
					// We need to keep the trailing Separator, do not use filepath.Join().
					content.URL = url
					content.Time = time.Now()
					content.Type = os.ModeDir
				default:
					content.URL = url
					content.Size = object.Size
					content.Time = object.Initiated
					content.Type = os.ModeTemporary
				}
				select {
				case <-ctx.Done():
					return
				case contentCh <- content:
				}
			}
		}
	default:
		isRecursive := false
		for object := range c.api.ListIncompleteUploads(ctx, b, o, isRecursive) {
			if object.Err != nil {
				select {
				case <-ctx.Done():
				case contentCh <- &ClientContent{
					Err: probe.NewError(object.Err),
				}:
				}
				return
			}
			content := &ClientContent{}
			url := c.targetURL.Clone()
			// Join bucket with - incoming object key.
			url.Path = c.buildAbsPath(b, object.Key)
			switch {
			case strings.HasSuffix(object.Key, string(c.targetURL.Separator)):
				// We need to keep the trailing Separator, do not use filepath.Join().
				content.URL = url
				content.Time = time.Now()
				content.Type = os.ModeDir
			default:
				content.URL = url
				content.Size = object.Size
				content.Time = object.Initiated
				content.Type = os.ModeTemporary
			}
			select {
			case <-ctx.Done():
				return
			case contentCh <- content:
			}
		}
	}
}

func (c *S3Client) listIncompleteRecursiveInRoutine(ctx context.Context, contentCh chan *ClientContent, opts ListOptions) {
	// get bucket and object from URL.
	b, o := c.url2BucketAndObject()
	switch {
	case b == "" && o == "":
		buckets, err := c.api.ListBuckets(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
			case contentCh <- &ClientContent{
				Err: probe.NewError(err),
			}:
			}
			return
		}
		sortBucketsNameWithSlash(buckets)
		isRecursive := true
		for _, bucket := range buckets {
			if opts.ShowDir != DirLast {
				select {
				case <-ctx.Done():
					return
				case contentCh <- c.bucketInfo2ClientContent(bucket):
				}
			}

			for object := range c.api.ListIncompleteUploads(ctx, bucket.Name, o, isRecursive) {
				if object.Err != nil {
					select {
					case <-ctx.Done():
						return
					case contentCh <- &ClientContent{
						Err: probe.NewError(object.Err),
					}:
					}
					return
				}
				url := c.targetURL.Clone()
				url.Path = c.buildAbsPath(bucket.Name, object.Key)
				content := &ClientContent{}
				content.URL = url
				content.Size = object.Size
				content.Time = object.Initiated
				content.Type = os.ModeTemporary
				select {
				case <-ctx.Done():
					return
				case contentCh <- content:
				}
			}

			if opts.ShowDir == DirLast {
				select {
				case <-ctx.Done():
					return
				case contentCh <- c.bucketInfo2ClientContent(bucket):
				}
			}
		}
	default:
		isRecursive := true
		for object := range c.api.ListIncompleteUploads(ctx, b, o, isRecursive) {
			if object.Err != nil {
				select {
				case <-ctx.Done():
					return
				case contentCh <- &ClientContent{
					Err: probe.NewError(object.Err),
				}:
				}
				return
			}
			url := c.targetURL.Clone()
			// Join bucket and incoming object key.
			url.Path = c.buildAbsPath(b, object.Key)
			content := &ClientContent{}
			content.URL = url
			content.Size = object.Size
			content.Time = object.Initiated
			content.Type = os.ModeTemporary
			select {
			case <-ctx.Done():
				return
			case contentCh <- content:
			}
		}
	}
}

// Join bucket and object name, keep the leading slash for directory markers
func (c *S3Client) joinPath(bucket string, objects ...string) string {
	p := bucket
	for _, o := range objects {
		p += string(c.targetURL.Separator) + o
	}
	return p
}

// Build new absolute URL path by joining path segments with URL path separator.
func (c *S3Client) buildAbsPath(bucket string, objects ...string) string {
	return string(c.targetURL.Separator) + c.joinPath(bucket, objects...)
}

// Convert objectInfo to ClientContent
func (c *S3Client) bucketInfo2ClientContent(bucket minio.BucketInfo) *ClientContent {
	content := &ClientContent{}
	url := c.targetURL.Clone()
	url.Path = c.buildAbsPath(bucket.Name)
	content.URL = url
	content.BucketName = bucket.Name
	content.Size = 0
	content.Time = bucket.CreationDate
	content.Type = os.ModeDir
	return content
}

// Convert objectInfo to ClientContent
func (c *S3Client) prefixInfo2ClientContent(bucket, prefix string) *ClientContent {
	// Join bucket and incoming object key.
	if bucket == "" {
		panic("should never happen, bucket cannot be empty")
	}
	content := &ClientContent{}
	url := c.targetURL.Clone()
	url.Path = c.buildAbsPath(bucket, prefix)
	content.URL = url
	content.BucketName = bucket
	content.Type = os.ModeDir
	content.Time = time.Now()
	return content
}

// Convert objectInfo to ClientContent
func (c *S3Client) objectInfo2ClientContent(bucket string, entry minio.ObjectInfo) *ClientContent {
	content := &ClientContent{}
	url := c.targetURL.Clone()
	// Join bucket and incoming object key.
	if bucket == "" {
		panic("should never happen, bucket cannot be empty")
	}
	url.Path = c.buildAbsPath(bucket, entry.Key)
	content.URL = url
	content.BucketName = bucket
	content.Size = entry.Size
	content.ETag = entry.ETag
	content.Time = entry.LastModified
	content.Expires = entry.Expires
	content.Expiration = entry.Expiration
	content.ExpirationRuleID = entry.ExpirationRuleID
	content.VersionID = entry.VersionID
	content.StorageClass = entry.StorageClass
	content.IsDeleteMarker = entry.IsDeleteMarker
	content.IsLatest = entry.IsLatest
	content.Restore = entry.Restore
	content.Metadata = map[string]string{}
	content.UserMetadata = map[string]string{}
	content.Tags = entry.UserTags

	content.ReplicationStatus = entry.ReplicationStatus
	for k, v := range entry.UserMetadata {
		content.UserMetadata[k] = v
	}
	for k := range entry.Metadata {
		content.Metadata[k] = entry.Metadata.Get(k)
	}
	attr, _ := parseAttribute(content.UserMetadata)
	if len(attr) > 0 {
		_, mtime, _ := parseAtimeMtime(attr)
		if !mtime.IsZero() {
			content.Time = mtime
		}
	}
	attr, _ = parseAttribute(content.Metadata)
	if len(attr) > 0 {
		_, mtime, _ := parseAtimeMtime(attr)
		if !mtime.IsZero() {
			content.Time = mtime
		}
	}

	if strings.HasSuffix(entry.Key, string(c.targetURL.Separator)) {
		content.Type = os.ModeDir
		if content.Time.IsZero() {
			content.Time = time.Now()
		}
	} else {
		content.Type = os.FileMode(0o664)
	}
	setChecksum := func(k, v string) {
		if v != "" {
			content.Checksum = map[string]string{k: v}
		}
	}
	setChecksum("CRC32", entry.ChecksumCRC32)
	setChecksum("CRC32C", entry.ChecksumCRC32C)
	setChecksum("SHA1", entry.ChecksumSHA1)
	setChecksum("SHA256", entry.ChecksumSHA256)
	return content
}

// Returns bucket stat info of current bucket.
func (c *S3Client) bucketStat(ctx context.Context, opts BucketStatOptions) (*ClientContent, *probe.Error) {
	if !opts.ignoreBucketExists {
		exists, e := c.api.BucketExists(ctx, opts.bucket)
		if e != nil {
			return nil, probe.NewError(e)
		}
		if !exists {
			return nil, probe.NewError(BucketDoesNotExist{Bucket: opts.bucket})
		}
	}
	return &ClientContent{
		URL: c.targetURL.Clone(), BucketName: opts.bucket, Time: time.Unix(0, 0), Type: os.ModeDir,
	}, nil
}

func (c *S3Client) listInRoutine(ctx context.Context, contentCh chan *ClientContent, opts ListOptions) {
	// get bucket and object from URL.
	b, o := c.url2BucketAndObject()
	if opts.ListZip && (b == "" || o == "") {
		contentCh <- &ClientContent{
			Err: probe.NewError(errors.New("listing zip files must provide bucket and object")),
		}
		return
	}
	switch {
	case b == "" && o == "":
		buckets, e := c.api.ListBuckets(ctx)
		if e != nil {
			contentCh <- &ClientContent{
				Err: probe.NewError(e),
			}
			return
		}
		for _, bucket := range buckets {
			contentCh <- c.bucketInfo2ClientContent(bucket)
		}
	case b != "" && !strings.HasSuffix(c.targetURL.Path, string(c.targetURL.Separator)) && o == "":
		content, err := c.bucketStat(ctx, BucketStatOptions{bucket: b})
		if err != nil {
			contentCh <- &ClientContent{Err: err.Trace(b)}
			return
		}
		contentCh <- content
	default:
		isRecursive := false
		for object := range c.listObjectWrapper(ctx, b, o, isRecursive, time.Time{}, false, false, opts.WithMetadata, -1, opts.ListZip) {
			if object.Err != nil {
				contentCh <- &ClientContent{
					Err: probe.NewError(object.Err),
				}
				return
			}
			contentCh <- c.objectInfo2ClientContent(b, object)
		}
	}
}

// S3 offers a range of storage classes designed for
// different use cases, following list captures these.
const (
	// General purpose.
	// s3StorageClassStandard = "STANDARD"
	// Infrequent access.
	// s3StorageClassInfrequent = "STANDARD_IA"
	// Reduced redundancy access.
	// s3StorageClassRedundancy = "REDUCED_REDUNDANCY"
	// Archive access.
	s3StorageClassGlacier = "GLACIER"
)

// Sorting buckets name with an additional '/' to make sure that a
// site-wide listing returns sorted output. This is crucial for
// correct diff/mirror calculation.
func sortBucketsNameWithSlash(bucketsInfo []minio.BucketInfo) {
	sort.Slice(bucketsInfo, func(i, j int) bool {
		return bucketsInfo[i].Name+"/" < bucketsInfo[j].Name+"/"
	})
}

func (c *S3Client) listRecursiveInRoutine(ctx context.Context, contentCh chan *ClientContent, opts ListOptions) {
	// get bucket and object from URL.
	b, o := c.url2BucketAndObject()
	switch {
	case b == "" && o == "":
		buckets, err := c.api.ListBuckets(ctx)
		if err != nil {
			contentCh <- &ClientContent{
				Err: probe.NewError(err),
			}
			return
		}
		sortBucketsNameWithSlash(buckets)
		for _, bucket := range buckets {
			if opts.ShowDir == DirFirst {
				contentCh <- c.bucketInfo2ClientContent(bucket)
			}

			isRecursive := true
			for object := range c.listObjectWrapper(ctx, bucket.Name, o, isRecursive, time.Time{}, false, false, opts.WithMetadata, -1, opts.ListZip) {
				if object.Err != nil {
					contentCh <- &ClientContent{
						Err: probe.NewError(object.Err),
					}
					return
				}
				contentCh <- c.objectInfo2ClientContent(bucket.Name, object)
			}

			if opts.ShowDir == DirLast {
				contentCh <- c.bucketInfo2ClientContent(bucket)
			}
		}
	default:
		isRecursive := true
		for object := range c.listObjectWrapper(ctx, b, o, isRecursive, time.Time{}, false, false, opts.WithMetadata, -1, opts.ListZip) {
			if object.Err != nil {
				contentCh <- &ClientContent{
					Err: probe.NewError(object.Err),
				}
				return
			}
			contentCh <- c.objectInfo2ClientContent(b, object)
		}
	}
}

// ShareDownload - get a usable presigned object url to share.
func (c *S3Client) ShareDownload(ctx context.Context, versionID string, expires time.Duration) (string, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	// No additional request parameters are set for the time being.
	reqParams := make(url.Values)
	if versionID != "" {
		reqParams.Set("versionId", versionID)
	}
	presignedURL, e := c.api.PresignedGetObject(ctx, bucket, object, expires, reqParams)
	if e != nil {
		return "", probe.NewError(e)
	}
	return presignedURL.String(), nil
}

// ShareUpload - get data for presigned post http form upload.
func (c *S3Client) ShareUpload(ctx context.Context, isRecursive bool, expires time.Duration, contentType string) (string, map[string]string, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	p := minio.NewPostPolicy()
	if e := p.SetExpires(UTCNow().Add(expires)); e != nil {
		return "", nil, probe.NewError(e)
	}
	if strings.TrimSpace(contentType) != "" || contentType != "" {
		// No need to verify for error here, since we have stripped out spaces.
		p.SetContentType(contentType)
	}
	if e := p.SetBucket(bucket); e != nil {
		return "", nil, probe.NewError(e)
	}
	if isRecursive {
		if e := p.SetKeyStartsWith(object); e != nil {
			return "", nil, probe.NewError(e)
		}
	} else {
		if e := p.SetKey(object); e != nil {
			return "", nil, probe.NewError(e)
		}
	}
	u, m, e := c.api.PresignedPostPolicy(ctx, p)
	if e != nil {
		return "", nil, probe.NewError(e)
	}
	return u.String(), m, nil
}

// SetObjectLockConfig - Set object lock configurataion of bucket.
func (c *S3Client) SetObjectLockConfig(ctx context.Context, mode minio.RetentionMode, validity uint64, unit minio.ValidityUnit) *probe.Error {
	bucket, object := c.url2BucketAndObject()

	if bucket == "" || object != "" {
		return errInvalidArgument().Trace(bucket, object)
	}

	// FIXME: This is too ugly, fix minio-go
	vuint := (uint)(validity)
	if mode != "" && vuint > 0 && unit != "" {
		e := c.api.SetBucketObjectLockConfig(ctx, bucket, &mode, &vuint, &unit)
		if e != nil {
			return probe.NewError(e).Trace(c.GetURL().String())
		}
		return nil
	}
	if mode == "" && vuint == 0 && unit == "" {
		e := c.api.SetBucketObjectLockConfig(ctx, bucket, nil, nil, nil)
		if e != nil {
			return probe.NewError(e).Trace(c.GetURL().String())
		}
		return nil
	}
	return errInvalidArgument().Trace(c.GetURL().String())
}

// PutObjectRetention - Set object retention for a given object.
func (c *S3Client) PutObjectRetention(ctx context.Context, versionID string, mode minio.RetentionMode, retainUntilDate time.Time, bypassGovernance bool) *probe.Error {
	bucket, object := c.url2BucketAndObject()

	var (
		modePtr            *minio.RetentionMode
		retainUntilDatePtr *time.Time
	)

	if mode != "" && retainUntilDate.IsZero() {
		return errInvalidArgument().Trace(c.GetURL().String())
	}

	if mode != "" {
		modePtr = &mode
		retainUntilDatePtr = &retainUntilDate
	}

	opts := minio.PutObjectRetentionOptions{
		VersionID:        versionID,
		RetainUntilDate:  retainUntilDatePtr,
		Mode:             modePtr,
		GovernanceBypass: bypassGovernance,
	}
	e := c.api.PutObjectRetention(ctx, bucket, object, opts)
	if e != nil {
		return probe.NewError(e).Trace(c.GetURL().String())
	}
	return nil
}

// GetObjectRetention - Get object retention for a given object.
func (c *S3Client) GetObjectRetention(ctx context.Context, versionID string) (minio.RetentionMode, time.Time, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	if object == "" {
		return "", time.Time{}, probe.NewError(ObjectNameEmpty{}).Trace(c.GetURL().String())
	}
	modePtr, untilPtr, e := c.api.GetObjectRetention(ctx, bucket, object, versionID)
	if e != nil {
		return "", time.Time{}, probe.NewError(e).Trace(c.GetURL().String())
	}
	var (
		mode  minio.RetentionMode
		until time.Time
	)
	if modePtr != nil {
		mode = *modePtr
	}
	if untilPtr != nil {
		until = *untilPtr
	}
	return mode, until, nil
}

// PutObjectLegalHold - Set object legal hold for a given object.
func (c *S3Client) PutObjectLegalHold(ctx context.Context, versionID string, lhold minio.LegalHoldStatus) *probe.Error {
	bucket, object := c.url2BucketAndObject()
	if lhold.IsValid() {
		opts := minio.PutObjectLegalHoldOptions{
			Status:    &lhold,
			VersionID: versionID,
		}
		e := c.api.PutObjectLegalHold(ctx, bucket, object, opts)
		if e != nil {
			return probe.NewError(e).Trace(c.GetURL().String())
		}
		return nil
	}
	return errInvalidArgument().Trace(c.GetURL().String())
}

// GetObjectLegalHold - Get object legal hold for a given object.
func (c *S3Client) GetObjectLegalHold(ctx context.Context, versionID string) (minio.LegalHoldStatus, *probe.Error) {
	var lhold minio.LegalHoldStatus
	bucket, object := c.url2BucketAndObject()
	opts := minio.GetObjectLegalHoldOptions{
		VersionID: versionID,
	}
	lhPtr, e := c.api.GetObjectLegalHold(ctx, bucket, object, opts)
	if e != nil {
		errResp := minio.ToErrorResponse(e)
		if errResp.Code != "NoSuchObjectLockConfiguration" {
			return "", probe.NewError(e).Trace(c.GetURL().String())
		}
		return "", nil
	}
	// lhPtr can be nil if there is no legalhold status set
	if lhPtr != nil {
		lhold = *lhPtr
	}
	return lhold, nil
}

// GetObjectLockConfig - Get object lock configuration of bucket.
func (c *S3Client) GetObjectLockConfig(ctx context.Context) (string, minio.RetentionMode, uint64, minio.ValidityUnit, *probe.Error) {
	bucket, object := c.url2BucketAndObject()

	if bucket == "" || object != "" {
		return "", "", 0, "", errInvalidArgument().Trace(bucket, object)
	}

	status, mode, validity, unit, e := c.api.GetObjectLockConfig(ctx, bucket)
	if e != nil {
		return "", "", 0, "", probe.NewError(e).Trace(c.GetURL().String())
	}

	if mode != nil && validity != nil && unit != nil {
		// FIXME: this is too ugly, fix minio-go
		vuint64 := uint64(*validity)
		return status, *mode, vuint64, *unit, nil
	}

	return status, "", 0, "", nil
}

// GetTags - Get tags of bucket or object.
func (c *S3Client) GetTags(ctx context.Context, versionID string) (map[string]string, *probe.Error) {
	bucketName, objectName := c.url2BucketAndObject()
	if bucketName == "" {
		return nil, probe.NewError(BucketNameEmpty{})
	}

	if objectName == "" {
		if versionID != "" {
			return nil, probe.NewError(errors.New("getting bucket tags does not support versioning parameters"))
		}

		tags, err := c.api.GetBucketTagging(ctx, bucketName)
		if err != nil {
			return nil, probe.NewError(err)
		}

		return tags.ToMap(), nil
	}

	tags, err := c.api.GetObjectTagging(ctx, bucketName, objectName, minio.GetObjectTaggingOptions{VersionID: versionID})
	if err != nil {
		return nil, probe.NewError(err)
	}

	return tags.ToMap(), nil
}

// SetTags - Set tags of bucket or object.
func (c *S3Client) SetTags(ctx context.Context, versionID, tagString string) *probe.Error {
	bucketName, objectName := c.url2BucketAndObject()
	if bucketName == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	tags, err := tags.Parse(tagString, objectName != "")
	if err != nil {
		return probe.NewError(err)
	}

	if objectName == "" {
		if versionID != "" {
			return probe.NewError(errors.New("setting bucket tags does not support versioning parameters"))
		}
		err = c.api.SetBucketTagging(ctx, bucketName, tags)
	} else {
		err = c.api.PutObjectTagging(ctx, bucketName, objectName, tags, minio.PutObjectTaggingOptions{VersionID: versionID})
	}

	if err != nil {
		return probe.NewError(err)
	}

	return nil
}

// DeleteTags - Delete tags of bucket or object
func (c *S3Client) DeleteTags(ctx context.Context, versionID string) *probe.Error {
	bucketName, objectName := c.url2BucketAndObject()
	if bucketName == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	var err error
	if objectName == "" {
		if versionID != "" {
			return probe.NewError(errors.New("setting bucket tags does not support versioning parameters"))
		}
		err = c.api.RemoveBucketTagging(ctx, bucketName)
	} else {
		err = c.api.RemoveObjectTagging(ctx, bucketName, objectName, minio.RemoveObjectTaggingOptions{VersionID: versionID})
	}

	if err != nil {
		return probe.NewError(err)
	}

	return nil
}

// GetLifecycle - Get current lifecycle configuration.
func (c *S3Client) GetLifecycle(ctx context.Context) (*lifecycle.Configuration, time.Time, *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return nil, time.Time{}, probe.NewError(BucketNameEmpty{})
	}

	config, updatedAt, e := c.api.GetBucketLifecycleWithInfo(ctx, bucket)
	if e != nil {
		return nil, time.Time{}, probe.NewError(e)
	}

	return config, updatedAt, nil
}

// SetLifecycle - Set lifecycle configuration on a bucket
func (c *S3Client) SetLifecycle(ctx context.Context, config *lifecycle.Configuration) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	if e := c.api.SetBucketLifecycle(ctx, bucket, config); e != nil {
		return probe.NewError(e)
	}

	return nil
}

// GetVersion - gets bucket version info.
func (c *S3Client) GetVersion(ctx context.Context) (config minio.BucketVersioningConfiguration, err *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return config, probe.NewError(BucketNameEmpty{})
	}
	var e error
	config, e = c.api.GetBucketVersioning(ctx, bucket)
	if e != nil {
		return config, probe.NewError(e)
	}

	return config, nil
}

// SetVersion - Set version configuration on a bucket
func (c *S3Client) SetVersion(ctx context.Context, status string, prefixes []string, excludeFolders bool) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	var err error
	switch status {
	case "enable":

		if len(prefixes) > 0 || excludeFolders {
			vc := minio.BucketVersioningConfiguration{
				Status:         minio.Enabled,
				ExcludeFolders: excludeFolders,
			}
			if len(prefixes) > 0 {
				eprefixes := make([]minio.ExcludedPrefix, 0, len(prefixes))
				for _, prefix := range prefixes {
					eprefixes = append(eprefixes, minio.ExcludedPrefix{Prefix: prefix})
				}
				vc.ExcludedPrefixes = eprefixes
			}
			err = c.api.SetBucketVersioning(ctx, bucket, vc)
		} else {
			err = c.api.EnableVersioning(ctx, bucket)
		}
	case "suspend":
		err = c.api.SuspendVersioning(ctx, bucket)
	default:
		return probe.NewError(fmt.Errorf("Invalid versioning status"))
	}
	return probe.NewError(err)
}

// GetReplication - gets replication configuration for a given bucket.
func (c *S3Client) GetReplication(ctx context.Context) (replication.Config, *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return replication.Config{}, probe.NewError(BucketNameEmpty{})
	}

	replicationCfg, e := c.api.GetBucketReplication(ctx, bucket)
	if e != nil {
		return replication.Config{}, probe.NewError(e)
	}
	return replicationCfg, nil
}

// RemoveReplication - removes replication configuration for a given bucket.
func (c *S3Client) RemoveReplication(ctx context.Context) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	e := c.api.RemoveBucketReplication(ctx, bucket)
	return probe.NewError(e)
}

// SetReplication sets replication configuration for a given bucket.
func (c *S3Client) SetReplication(ctx context.Context, cfg *replication.Config, opts replication.Options) *probe.Error {
	bucket, objectPrefix := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	opts.Prefix = objectPrefix
	switch opts.Op {
	case replication.AddOption:
		if e := cfg.AddRule(opts); e != nil {
			return probe.NewError(e)
		}
	case replication.SetOption:
		if e := cfg.EditRule(opts); e != nil {
			return probe.NewError(e)
		}
	case replication.RemoveOption:
		if e := cfg.RemoveRule(opts); e != nil {
			return probe.NewError(e)
		}
	case replication.ImportOption:
	default:
		return probe.NewError(fmt.Errorf("Invalid replication option"))
	}
	if e := c.api.SetBucketReplication(ctx, bucket, *cfg); e != nil {
		return probe.NewError(e)
	}
	return nil
}

// GetReplicationMetrics - Get replication metrics for a given bucket.
func (c *S3Client) GetReplicationMetrics(ctx context.Context) (replication.MetricsV2, *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return replication.MetricsV2{}, probe.NewError(BucketNameEmpty{})
	}

	metrics, e := c.api.GetBucketReplicationMetricsV2(ctx, bucket)
	if e != nil {
		return replication.MetricsV2{}, probe.NewError(e)
	}
	return metrics, nil
}

// ResetReplication - kicks off replication again on previously replicated objects if existing object
// replication is enabled in the replication config.Optional to provide a timestamp
func (c *S3Client) ResetReplication(ctx context.Context, before time.Duration, tgtArn string) (rinfo replication.ResyncTargetsInfo, err *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return rinfo, probe.NewError(BucketNameEmpty{})
	}

	rinfo, e := c.api.ResetBucketReplicationOnTarget(ctx, bucket, before, tgtArn)
	if e != nil {
		return rinfo, probe.NewError(e)
	}
	return rinfo, nil
}

// ReplicationResyncStatus - gets status of replication resync for this target arn
func (c *S3Client) ReplicationResyncStatus(ctx context.Context, arn string) (rinfo replication.ResyncTargetsInfo, err *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return rinfo, probe.NewError(BucketNameEmpty{})
	}

	rinfo, e := c.api.GetBucketReplicationResyncStatus(ctx, bucket, arn)
	if e != nil {
		return rinfo, probe.NewError(e)
	}
	return rinfo, nil
}

// GetEncryption - gets bucket encryption info.
func (c *S3Client) GetEncryption(ctx context.Context) (algorithm, keyID string, err *probe.Error) {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return "", "", probe.NewError(BucketNameEmpty{})
	}

	config, e := c.api.GetBucketEncryption(ctx, bucket)
	if e != nil {
		return "", "", probe.NewError(e)
	}
	for _, rule := range config.Rules {
		algorithm = rule.Apply.SSEAlgorithm
		if rule.Apply.KmsMasterKeyID != "" {
			keyID = rule.Apply.KmsMasterKeyID
			break
		}
	}
	return algorithm, keyID, nil
}

// SetEncryption - Set encryption configuration on a bucket
func (c *S3Client) SetEncryption(ctx context.Context, encType, kmsKeyID string) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	var config *sse.Configuration
	switch strings.ToLower(encType) {
	case "sse-kms":
		config = sse.NewConfigurationSSEKMS(kmsKeyID)
	case "sse-s3":
		config = sse.NewConfigurationSSES3()
	default:
		return probe.NewError(fmt.Errorf("Invalid encryption algorithm %s", encType))
	}
	if err := c.api.SetBucketEncryption(ctx, bucket, config); err != nil {
		return probe.NewError(err)
	}
	return nil
}

// DeleteEncryption - removes encryption configuration on a bucket
func (c *S3Client) DeleteEncryption(ctx context.Context) *probe.Error {
	bucket, _ := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	if err := c.api.RemoveBucketEncryption(ctx, bucket); err != nil {
		return probe.NewError(err)
	}
	return nil
}

// GetBucketInfo gets info about a bucket
func (c *S3Client) GetBucketInfo(ctx context.Context) (BucketInfo, *probe.Error) {
	var b BucketInfo
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return b, probe.NewError(BucketNameEmpty{})
	}
	if object != "" {
		return b, probe.NewError(InvalidArgument{})
	}
	content, err := c.bucketStat(ctx, BucketStatOptions{bucket: bucket})
	if err != nil {
		return b, err.Trace(bucket)
	}
	b.Key = bucket
	b.URL = content.URL
	b.Size = content.Size
	b.Type = content.Type
	b.Date = content.Time
	if vcfg, err := c.GetVersion(ctx); err == nil {
		b.Versioning.Status = vcfg.Status
		b.Versioning.MFADelete = vcfg.MFADelete
	}
	if enabled, mode, validity, unit, err := c.api.GetObjectLockConfig(ctx, bucket); err == nil {
		if mode != nil {
			b.Locking.Mode = *mode
		}
		b.Locking.Enabled = enabled
		if validity != nil && unit != nil {
			vuint64 := uint64(*validity)
			b.Locking.Validity = fmt.Sprintf("%d%s", vuint64, unit)
		}
	}

	if rcfg, err := c.GetReplication(ctx); err == nil {
		if !rcfg.Empty() {
			b.Replication.Enabled = true
		}
	}
	if algo, keyID, err := c.GetEncryption(ctx); err == nil {
		b.Encryption.Algorithm = algo
		b.Encryption.KeyID = keyID
	}

	if pType, policyStr, err := c.GetAccess(ctx); err == nil {
		b.Policy.Type = pType
		b.Policy.Text = policyStr
	}
	location, e := c.api.GetBucketLocation(ctx, bucket)
	if e != nil {
		return b, probe.NewError(e)
	}
	b.Location = location
	if tags, err := c.GetTags(ctx, ""); err == nil {
		b.Tagging = tags
	}
	if lfc, _, err := c.GetLifecycle(ctx); err == nil {
		b.ILM.Config = lfc
	}
	if nfc, err := c.api.GetBucketNotification(ctx, bucket); err == nil {
		b.Notification.Config = nfc
	}
	return b, nil
}

// Restore gets a copy of an archived object
func (c *S3Client) Restore(ctx context.Context, versionID string, days int) *probe.Error {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return probe.NewError(BucketNameEmpty{})
	}
	if object == "" {
		return probe.NewError(ObjectNameEmpty{})
	}

	req := minio.RestoreRequest{}
	req.SetDays(days)
	req.SetGlacierJobParameters(minio.GlacierJobParameters{Tier: minio.TierExpedited})
	if err := c.api.RestoreObject(ctx, bucket, object, versionID, req); err != nil {
		return probe.NewError(err)
	}
	return nil
}

// GetPart gets an object in a given number of parts
func (c *S3Client) GetPart(ctx context.Context, part int) (io.ReadCloser, *probe.Error) {
	bucket, object := c.url2BucketAndObject()
	if bucket == "" {
		return nil, probe.NewError(BucketNameEmpty{})
	}
	if object == "" {
		return nil, probe.NewError(ObjectNameEmpty{})
	}
	getOO := minio.GetObjectOptions{}
	if part > 0 {
		getOO.PartNumber = part
	}
	reader, e := c.api.GetObject(ctx, bucket, object, getOO)
	if e != nil {
		return nil, probe.NewError(e)
	}
	return reader, nil
}

// SetBucketCors - Set bucket cors configuration.
func (c *S3Client) SetBucketCors(ctx context.Context, corsXML []byte) *probe.Error {
	bucketName, _ := c.url2BucketAndObject()
	if bucketName == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	corsCfg, err := cors.ParseBucketCorsConfig(bytes.NewReader(corsXML))
	if err != nil {
		return probe.NewError(err)
	}

	err = c.api.SetBucketCors(ctx, bucketName, corsCfg)
	if err != nil {
		return probe.NewError(err)
	}
	return nil
}

// GetBucketCors - Get bucket cors configuration.
func (c *S3Client) GetBucketCors(ctx context.Context) (*cors.Config, *probe.Error) {
	bucketName, _ := c.url2BucketAndObject()
	if bucketName == "" {
		return nil, probe.NewError(BucketNameEmpty{})
	}

	corsCfg, err := c.api.GetBucketCors(ctx, bucketName)
	if err != nil {
		return nil, probe.NewError(err)
	}

	return corsCfg, nil
}

// DeleteBucketCors - Delete bucket cors configuration.
func (c *S3Client) DeleteBucketCors(ctx context.Context) *probe.Error {
	bucketName, _ := c.url2BucketAndObject()
	if bucketName == "" {
		return probe.NewError(BucketNameEmpty{})
	}

	err := c.api.SetBucketCors(ctx, bucketName, nil)
	if err != nil {
		return probe.NewError(err)
	}

	return nil
}
