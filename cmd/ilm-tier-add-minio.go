// Copyright (c) 2015-2023 MinIO, Inc.
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
	"github.com/minio/cli"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/pkg/probe"
)

var adminTierAddMinioFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "endpoint",
		Value: "",
		Usage: "remote tier endpoint. e.g https://s3.amazonaws.com",
	},
	cli.StringFlag{
		Name:  "region",
		Value: "",
		Usage: "remote tier region. e.g us-west-2",
	},
	cli.StringFlag{
		Name:  "access-key",
		Value: "",
		Usage: "MinIO object storage access-key",
	},
	cli.StringFlag{
		Name:  "secret-key",
		Value: "",
		Usage: "MinIO object storage secret-key",
	},
	cli.StringFlag{
		Name:  "bucket",
		Value: "",
		Usage: "remote tier bucket",
	},
	cli.StringFlag{
		Name:  "prefix",
		Value: "",
		Usage: "remote tier prefix",
	},
}

var adminTierAddMinioCmd = cli.Command{
	Name:         "minio",
	Usage:        "add a new MinIO remote tier target",
	Action:       mainAdminTierAddMinio,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(globalFlags, adminTierAddMinioFlags...),
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} ALIAS TIER-NAME [FLAGS]

TIER-NAME:
  Name of the remote tier target. e.g WARM-TIER

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  1. Configure a new remote tier which transitions objects to a bucket in a MinIO deployment:
     {{.Prompt}} {{.HelpName}} minio myminio WARM-MINIO-TIER --endpoint https://warm-minio.com \
        --access-key ACCESSKEY --secret-key SECRETKEY --bucket mybucket --prefix myprefix/
`,
}

func fetchMinioTierConfig(ctx *cli.Context, tierName string) *madmin.TierConfig {
	accessKey := ctx.String("access-key")
	secretKey := ctx.String("secret-key")
	if accessKey == "" || secretKey == "" {
		fatalIf(errInvalidArgument().Trace(), "MinIO remote tier requires access credentials")
	}
	bucket := ctx.String("bucket")
	if bucket == "" {
		fatalIf(errInvalidArgument().Trace(), "MinIO remote tier requires target bucket")
	}

	endpoint := ctx.String("endpoint")
	if endpoint == "" {
		fatalIf(errInvalidArgument().Trace(), "MinIO remote tier requires target endpoint")
	}

	minioOpts := []madmin.MinIOOptions{}
	prefix := ctx.String("prefix")
	if prefix != "" {
		minioOpts = append(minioOpts, madmin.MinIOPrefix(prefix))
	}

	region := ctx.String("region")
	if region != "" {
		minioOpts = append(minioOpts, madmin.MinIORegion(region))
	}

	minioCfg, e := madmin.NewTierMinIO(tierName, endpoint, accessKey, secretKey, bucket, minioOpts...)
	fatalIf(probe.NewError(e), "Invalid configuration for MinIO tier")

	return minioCfg
}

func mainAdminTierAddMinio(ctx *cli.Context) error {
	return genericTierAddCmd(ctx, madmin.MinIO)
}
