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
	"strings"

	"github.com/fatih/color"
	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/pkg/probe"
	"github.com/minio/pkg/v3/console"
)

var ilmTierAddSubcommands = []cli.Command{
	adminTierAddAzureCmd,
	adminTierAddGCSCmd,
	adminTierAddAWSCmd,
	adminTierAddMinioCmd,
}

var adminTierAddCmd = cli.Command{
	Name:            "add",
	Usage:           "add a new remote tier target",
	Action:          mainAdminTierAdd,
	OnUsageError:    onUsageError,
	Flags:           globalFlags,
	Before:          setGlobalsFromContext,
	HideHelpCommand: true,
	Subcommands:     ilmTierAddSubcommands,
}

func mainAdminTierAdd(ctx *cli.Context) error {
	commandNotFound(ctx, ilmTierAddSubcommands)
	return nil
}

type tierMessage struct {
	op         string
	Status     string            `json:"status"`
	TierName   string            `json:"tierName"`
	TierType   string            `json:"tierType"`
	Endpoint   string            `json:"tierEndpoint"`
	Bucket     string            `json:"bucket"`
	Prefix     string            `json:"prefix,omitempty"`
	Region     string            `json:"region,omitempty"`
	TierParams map[string]string `json:"tierParams,omitempty"`
}

// String returns string representation of msg
func (msg *tierMessage) String() string {
	switch msg.op {
	case "add":
		addMsg := fmt.Sprintf("Added remote tier %s of type %s", msg.TierName, msg.TierType)
		return console.Colorize("TierMessage", addMsg)
	case "rm":
		rmMsg := fmt.Sprintf("Removed remote tier %s", msg.TierName)
		return console.Colorize("TierMessage", rmMsg)
	case "verify":
		verifyMsg := fmt.Sprintf("Verified remote tier %s", msg.TierName)
		return console.Colorize("TierMessage", verifyMsg)
	case "check":
		checkMsg := fmt.Sprintf("Remote tier connectivity check for %s was successful", msg.TierName)
		return console.Colorize("TierMessage", checkMsg)
	case "edit":
		editMsg := fmt.Sprintf("Updated remote tier %s", msg.TierName)
		return console.Colorize("TierMessage", editMsg)
	}
	return ""
}

// JSON returns json encoded msg
func (msg *tierMessage) JSON() string {
	jsonMessageBytes, e := json.MarshalIndent(msg, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(jsonMessageBytes)
}

// SetTierConfig sets TierConfig related fields
func (msg *tierMessage) SetTierConfig(sCfg *madmin.TierConfig) {
	msg.TierName = sCfg.Name
	msg.TierType = sCfg.Type.String()
	msg.Endpoint = sCfg.Endpoint()
	msg.Bucket = sCfg.Bucket()
	msg.Prefix = sCfg.Prefix()
	msg.Region = sCfg.Region()
	switch sCfg.Type {
	case madmin.S3:
		msg.TierParams = map[string]string{
			"storageClass": sCfg.S3.StorageClass,
		}
	}
}

// checkAdminTierAddSyntax validates all the positional arguments
func checkAdminTierAddSyntax(ctx *cli.Context) {
	argsNr := len(ctx.Args())
	if argsNr < 2 {
		showCommandHelpAndExit(ctx, 1) // last argument is exit code
	}
	if argsNr > 2 {
		fatalIf(errInvalidArgument().Trace(ctx.Args().Tail()...),
			"Incorrect number of arguments for tier add command.")
	}
}

func genericTierAddCmd(ctx *cli.Context, tierType madmin.TierType) error {
	checkAdminTierAddSyntax(ctx)

	console.SetColor("TierMessage", color.New(color.FgGreen))

	args := ctx.Args()

	aliasedURL := args.Get(0)
	tierName := strings.ToUpper(args.Get(1))
	if tierName == "" {
		fatalIf(errInvalidArgument(), "Tier name can't be empty")
	}

	// Create a new MinIO Admin Client
	client, cerr := newAdminClient(aliasedURL)
	fatalIf(cerr, "Unable to initialize admin connection.")

	var tCfg *madmin.TierConfig

	switch tierType {
	case madmin.MinIO:
		tCfg = fetchMinioTierConfig(ctx, tierName)
	case madmin.S3:
		tCfg = fetchS3TierConfig(ctx, tierName)
	case madmin.Azure:
		tCfg = fetchAzureTierConfig(ctx, tierName)
	case madmin.GCS:
		tCfg = fetchGCSTierConfig(ctx, tierName)
	}

	ignoreInUse := ctx.Bool("force")
	if ignoreInUse {
		fatalIf(probe.NewError(client.AddTierIgnoreInUse(globalContext, tCfg)).Trace(args...), "Unable to configure remote tier target")
	} else {
		fatalIf(probe.NewError(client.AddTier(globalContext, tCfg)).Trace(args...), "Unable to configure remote tier target")
	}

	msg := &tierMessage{
		op:     ctx.Command.Name,
		Status: "success",
	}
	msg.SetTierConfig(tCfg)
	printMsg(msg)
	return nil
}
