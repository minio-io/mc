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
	"fmt"

	"github.com/minio/cli"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/pkg/probe"
)

var adminTierAddS3Flags = []cli.Flag{
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
		Usage: "AWS S3 or compatible object storage access-key",
	},
	cli.StringFlag{
		Name:  "secret-key",
		Value: "",
		Usage: "AWS S3 or compatible object storage secret-key",
	},
	cli.BoolFlag{
		Name:  "use-aws-role",
		Usage: "use AWS S3 role",
	},
	cli.StringFlag{
		Name:  "aws-role-arn",
		Usage: "use AWS S3 role name",
	},
	cli.StringFlag{
		Name:  "aws-web-identity-file",
		Usage: "use AWS S3 web identity file",
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
	cli.StringFlag{
		Name:  "storage-class",
		Value: "",
		Usage: "remote tier storage-class",
	},
}

var adminTierAddAWSCmd = cli.Command{
	Name:         "s3",
	Usage:        "add a new AWS/S3 compatible remote tier target",
	Action:       mainAdminTierAddS3,
	OnUsageError: onUsageError,
	Before:       setGlobalsFromContext,
	Flags:        append(globalFlags, adminTierAddS3Flags...),
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
  1. Configure a new remote tier which transitions objects to a bucket in AWS S3 with STANDARD storage class:
     {{.Prompt}} {{.HelpName}} s3 myminio S3TIER --endpoint https://s3.amazonaws.com \
        --access-key ACCESSKEY --secret-key SECRETKEY --bucket mys3bucket --prefix mys3prefix/ \
        --storage-class "STANDARD" --region us-west-2
`,
}

const (
	s3Standard          = "STANDARD"
	s3ReducedRedundancy = "REDUCED_REDUNDANCY"
)

func fetchS3TierConfig(ctx *cli.Context, tierName string) *madmin.TierConfig {
	accessKey := ctx.IsSet("access-key")
	secretKey := ctx.IsSet("secret-key")
	useAwsRole := ctx.IsSet("use-aws-role")
	awsRoleArn := ctx.IsSet("aws-role-arn")
	awsWebIdentity := ctx.IsSet("aws-web-identity-file")

	// Extensive flag check
	switch {
	case !accessKey && !secretKey && !useAwsRole && !awsRoleArn && !awsWebIdentity:
		fatalIf(errInvalidArgument().Trace(), "No authentication mechanism was provided")
	case (accessKey || secretKey) && (useAwsRole || awsRoleArn || awsWebIdentity):
		fatalIf(errInvalidArgument().Trace(), "Static credentials cannot be combined with AWS role authentication")
	case useAwsRole && (awsRoleArn || awsWebIdentity):
		fatalIf(errInvalidArgument().Trace(), "--use-aws-role cannot be combined with --aws-role-arn or --aws-web-identity-file")
	case (awsRoleArn && !awsWebIdentity) || (!awsRoleArn && awsWebIdentity):
		fatalIf(errInvalidArgument().Trace(), "Both --use-aws-role and --aws-web-identity-file are required to enable web identity token based authentication")
	case (accessKey && !secretKey) || (!accessKey && secretKey):
		fatalIf(errInvalidArgument().Trace(), "Both --access-key and --secret-key are required to enable static credentials authentication")

	}

	bucket := ctx.String("bucket")
	if bucket == "" {
		fatalIf(errInvalidArgument().Trace(), "S3 remote tier requires target bucket")
	}

	s3Opts := []madmin.S3Options{}
	prefix := ctx.String("prefix")
	if prefix != "" {
		s3Opts = append(s3Opts, madmin.S3Prefix(prefix))
	}

	endpoint := ctx.String("endpoint")
	if endpoint != "" {
		s3Opts = append(s3Opts, madmin.S3Endpoint(endpoint))
	}

	region := ctx.String("region")
	if region != "" {
		s3Opts = append(s3Opts, madmin.S3Region(region))
	}

	s3SC := ctx.String("storage-class")
	if s3SC != "" {
		if s3SC != s3Standard && s3SC != s3ReducedRedundancy {
			fatalIf(errInvalidArgument().Trace(), fmt.Sprintf("unsupported storage-class type %s", s3SC))
		}
		s3Opts = append(s3Opts, madmin.S3StorageClass(s3SC))
	}
	if ctx.IsSet("use-aws-role") {
		s3Opts = append(s3Opts, madmin.S3AWSRole())
	}
	if ctx.IsSet("aws-role-arn") {
		s3Opts = append(s3Opts, madmin.S3AWSRoleARN(ctx.String("aws-role-arn")))
	}
	if ctx.IsSet("aws-web-identity-file") {
		s3Opts = append(s3Opts, madmin.S3AWSRoleWebIdentityTokenFile(ctx.String("aws-web-identity-file")))
	}
	s3Cfg, e := madmin.NewTierS3(tierName, ctx.String("access-key"), ctx.String("secret-key"), bucket, s3Opts...)
	fatalIf(probe.NewError(e), "Invalid configuration for AWS S3 compatible remote tier")

	return s3Cfg
}

func mainAdminTierAddS3(ctx *cli.Context) error {
	return genericTierAddCmd(ctx, madmin.S3)
}
