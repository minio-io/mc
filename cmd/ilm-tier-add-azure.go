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

var adminTierAddAzureFlags = []cli.Flag{
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
		Name:  "account-name",
		Value: "",
		Usage: "Azure Blob Storage account name",
	},
	cli.StringFlag{
		Name:  "account-key",
		Value: "",
		Usage: "Azure Blob Storage account key",
	},
	cli.StringFlag{
		Name:  "sp-tenant-id",
		Value: "",
		Usage: "Directory ID for the Azure service principal account",
	},
	cli.StringFlag{
		Name:  "sp-client-id",
		Value: "",
		Usage: "The client ID of the Azure service principal account",
	},
	cli.StringFlag{
		Name:  "sp-client-secret",
		Value: "",
		Usage: "The client secret of the Azure service principal account",
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

var adminTierAddAzureCmd = cli.Command{
	Name:         "azure",
	Usage:        "add a new Azure remote tier target",
	Action:       mainAdminTierAddAzure,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(globalFlags, adminTierAddAzureFlags...),
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
  1. Configure a new remote tier which transitions objects to a bucket in Azure Blob Storage:
     {{.Prompt}} {{.HelpName}} azure myminio AZTIER --account-name ACCOUNT-NAME --account-key ACCOUNT-KEY \
        --bucket myazurebucket --prefix myazureprefix/

`,
}

func fetchAzureTierConfig(ctx *cli.Context, tierName string) *madmin.TierConfig {
	accountName := ctx.String("account-name")
	accountKey := ctx.String("account-key")
	if accountName == "" {
		fatalIf(errDummy().Trace(), "Azure remote tier requires the storage account name")
	}

	if accountKey == "" && (ctx.String("az-sp-tenant-id") == "" || ctx.String("az-sp-client-id") == "" || ctx.String("az-sp-client-secret") == "") {
		fatalIf(errDummy().Trace(), "Azure remote tier requires static credentials OR service principal credentials")
	}

	bucket := ctx.String("bucket")
	if bucket == "" {
		fatalIf(errDummy().Trace(), "Azure remote tier requires target bucket")
	}

	azOpts := []madmin.AzureOptions{}
	endpoint := ctx.String("endpoint")
	if endpoint != "" {
		azOpts = append(azOpts, madmin.AzureEndpoint(endpoint))
	}

	region := ctx.String("region")
	if region != "" {
		azOpts = append(azOpts, madmin.AzureRegion(region))
	}

	prefix := ctx.String("prefix")
	if prefix != "" {
		azOpts = append(azOpts, madmin.AzurePrefix(prefix))
	}

	if ctx.String("sp-tenant-id") != "" || ctx.String("sp-client-id") != "" || ctx.String("sp-client-secret") != "" {
		azOpts = append(azOpts, madmin.AzureServicePrincipal(ctx.String("sp-tenant-id"), ctx.String("sp-client-id"), ctx.String("sp-client-secret")))
	}

	azCfg, e := madmin.NewTierAzure(tierName, accountName, accountKey, bucket, azOpts...)
	fatalIf(probe.NewError(e), "Invalid configuration for Azure Blob Storage remote tier")

	return azCfg
}

func mainAdminTierAddAzure(ctx *cli.Context) error {
	return genericTierAddCmd(ctx, madmin.Azure)
}
