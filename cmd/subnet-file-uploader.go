// Copyright (c) 2015-2024 MinIO, Inc.
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
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/minio/madmin-go/v3/estream"
)

// SubnetFileUploader - struct to upload files to SUBNET
type SubnetFileUploader struct {
	alias             string        // used for saving api-key and license from response
	filename          string        // filename passed in the SUBNET request
	FilePath          string        // file to upload
	ReqURL            string        // SUBNET upload URL
	Params            url.Values    // query params to be sent in the request
	Headers           SubnetHeaders // headers to be sent in the request
	AutoCompress      bool          // whether to compress (zst) the file before uploading
	DeleteAfterUpload bool          // whether to delete the file after successful upload
	AutoEncrypt       bool          // Encrypt content.
	PubKey            []byte        // Custom public encryption key.
}

// UploadFileToSubnet - uploads the file to SUBNET
func (i *SubnetFileUploader) UploadFileToSubnet() (string, error) {
	req, e := i.subnetUploadReq()
	if e != nil {
		return "", e
	}

	resp, e := subnetReqDo(req, i.Headers)
	if e != nil {
		return "", e
	}

	if i.DeleteAfterUpload {
		os.Remove(i.FilePath)
	}

	// ensure that both api-key and license from
	// SUBNET response are saved in the config
	if len(i.alias) > 0 {
		extractAndSaveSubnetCreds(i.alias, resp)
	}

	return resp, nil
}

func (i *SubnetFileUploader) updateParams() {
	if i.Params == nil {
		i.Params = url.Values{}
	}

	if i.filename == "" {
		i.filename = filepath.Base(i.FilePath)
	}

	i.AutoCompress = i.AutoCompress && !strings.HasSuffix(strings.ToLower(i.FilePath), ".zst")
	if i.AutoCompress {
		i.filename += ".zst"
		i.Params.Add("auto-compression", "zstd")
	}
	if i.AutoEncrypt || len(i.PubKey) >= 0 {
		i.Params.Add("encrypted", "true")
		i.filename += ".enc"
	}

	i.Params.Add("filename", i.filename)
	i.ReqURL += "?" + i.Params.Encode()
}

func (i *SubnetFileUploader) subnetUploadReq() (*http.Request, error) {
	i.updateParams()

	r, w := io.Pipe()
	mwriter := multipart.NewWriter(w)
	contentType := mwriter.FormDataContentType()

	go func() {
		var (
			part io.Writer
			e    error
		)
		var errfn func(string) error
		defer func() {
			mwriter.Close()
			w.CloseWithError(e)
			if e != nil && errfn != nil {
				errfn(e.Error())
			}
		}()

		file, e := os.Open(i.FilePath)
		if e != nil {
			return
		}
		defer file.Close()

		part, e = mwriter.CreateFormFile("file", i.filename)
		if e != nil {
			return
		}
		if i.AutoEncrypt || len(i.PubKey) > 0 {
			sw := estream.NewWriter(part)
			defer sw.Close()
			errfn = sw.AddError
			key := i.PubKey
			if key == nil {
				key, e = base64.StdEncoding.DecodeString(defaultPublicKey)
				if e != nil {
					return
				}
			}
			pk, e := bytesToPublicKey(key)
			if e != nil {
				sw.AddError(e.Error())
				return
			}
			e = sw.AddKeyEncrypted(pk)
			if e != nil {
				sw.AddError(e.Error())
				return
			}
			wc, e := sw.AddEncryptedStream(strings.TrimSuffix(i.filename, ".enc"), nil)
			if e != nil {
				sw.AddError(e.Error())
				return
			}
			defer wc.Close()
			part = wc
		}

		if i.AutoCompress {
			z, _ := zstd.NewWriter(part, zstd.WithEncoderConcurrency(2))
			sz, err := file.Stat()
			if err == nil {
				// Set file size if we can.
				z.ResetContentSize(part, sz.Size())
			}
			defer z.Close()
			_, e = z.ReadFrom(file)
		} else {
			_, e = io.Copy(part, file)
		}
	}()

	req, e := http.NewRequest(http.MethodPost, i.ReqURL, r)
	if e != nil {
		return nil, e
	}
	req.Header.Add("Content-Type", contentType)

	return req, nil
}

func bytesToPublicKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block != nil {
		pub = block.Bytes
	}
	key, err := x509.ParsePKCS1PublicKey(pub)
	if err != nil {
		return nil, err
	}
	return key, nil
}
