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
	"os"

	"github.com/minio/cli"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/pkg/probe"
)

var adminTierAddGCSFlags = []cli.Flag{
	cli.StringFlag{
		Name:  "region",
		Value: "",
		Usage: "remote tier region. e.g us-west-2",
	},
	cli.StringFlag{
		Name:  "credentials-file",
		Value: "",
		Usage: "path to Google Cloud Storage credentials file",
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

var adminTierAddGCSCmd = cli.Command{
	Name:         "gcs",
	Usage:        "add a new GCS remote tier target",
	Action:       mainAdminTierAddGCS,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(globalFlags, adminTierAddGCSFlags...),
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
  1. Configure a new remote tier which transitions objects to a bucket in Google Cloud Storage:
     {{.Prompt}} {{.HelpName}} gcs myminio GCSTIER --credentials-file /path/to/credentials.json \
        --bucket mygcsbucket  --prefix mygcsprefix/
`,
}

func fetchGCSTierConfig(ctx *cli.Context, tierName string) *madmin.TierConfig {
	bucket := ctx.String("bucket")
	if bucket == "" {
		fatalIf(errInvalidArgument().Trace(), "GCS remote requires target bucket")
	}

	gcsOpts := []madmin.GCSOptions{}
	prefix := ctx.String("prefix")
	if prefix != "" {
		gcsOpts = append(gcsOpts, madmin.GCSPrefix(prefix))
	}

	region := ctx.String("region")
	if region != "" {
		gcsOpts = append(gcsOpts, madmin.GCSRegion(region))
	}

	credsPath := ctx.String("credentials-file")
	credsBytes, e := os.ReadFile(credsPath)
	fatalIf(probe.NewError(e), "Failed to read credentials file")

	gcsCfg, e := madmin.NewTierGCS(tierName, credsBytes, bucket, gcsOpts...)
	fatalIf(probe.NewError(e), "Invalid configuration for Google Cloud Storage remote tier")

	return gcsCfg
}

func mainAdminTierAddGCS(ctx *cli.Context) error {
	return genericTierAddCmd(ctx, madmin.GCS)
}
