/*
 * MinIO Client (C) 2019 MinIO, Inc.
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
	"os"

	"github.com/minio/cli"
	"github.com/minio/minio/pkg/console"
)

/*var ilmRemoveFlags = []cli.Flag{
	cli.StringFlag{
		Name: "recursive",
	},
}*/

var ilmRemoveCmd = cli.Command{
	Name:   "remove",
	Usage:  "Remove/Delte Information bucket lifecycle management information.",
	Action: mainLifecycleRemove,
	Before: setGlobalsFromContext,
	Flags:  globalFlags,
	CustomHelpTemplate: `Name:
	{{.HelpName}} - {{.Usage}}

USAGE:
	{{.HelpName}} TARGET

DESCRIPTION:
	Remove the lifecycle configuration for the bucket/object.

TARGET:
	This argument needs to be in the format of 'alias/bucket/prefix' or 'alias/bucket'

EXAMPLES:
1. Delete the lifecycle management configuration provided for the test34bucket on alias s3 .
	{{.Prompt}} {{.HelpName}} s3/test34bucket
`,
}

// checkIlmSetSyntax - validate arguments passed by a user
func checkIlmRemoveSyntax(ctx *cli.Context) {
	// fmt.Println(len(ctx.Args()))
	if len(ctx.Args()) == 0 || len(ctx.Args()) > 1 {
		cli.ShowCommandHelp(ctx, "remove")
		os.Exit(globalErrorExitStatus)
	}
}

func ilmRemove(urlStr string) error {
	bkt := getBucketNameFromURL(urlStr)
	api, apierr := getMinioClient(urlStr)
	if apierr != nil {
		console.Errorln("Error removing bucket lifecycle configuration. " + apierr.String())
		return apierr.ToGoError()
	}
	if api == nil {
		console.Errorln("Unable to call the API to remove bucket lifecycle.")
		return errInvalidTarget(urlStr).ToGoError()

	}
	if ilmErr := api.SetBucketLifecycle(bkt, ""); ilmErr != nil {
		return ilmErr
	}
	return nil
}

func mainLifecycleRemove(ctx *cli.Context) error {
	checkIlmRemoveSyntax(ctx)
	setColorScheme()
	args := ctx.Args()
	objectURL := args.Get(0)
	if ilmRmErr := ilmRemove(objectURL); ilmRmErr != nil {
		console.Errorln("Unable to remove lifecycle information of object/bucket.")
		return ilmRmErr
	}
	successStr := "Removed Lifecycle Configuration: " + objectURL
	console.Println(console.Colorize(fieldThemeResultSuccess, successStr))
	return nil
}
