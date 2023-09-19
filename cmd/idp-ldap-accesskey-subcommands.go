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
	"errors"
	"fmt"
	"time"

	"github.com/minio/cli"
	json "github.com/minio/colorjson"
	"github.com/minio/madmin-go/v3"
	"github.com/minio/mc/pkg/probe"
)

var idpLdapAccesskeyListFlags = []cli.Flag{
	cli.BoolFlag{
		Name:  "users, u",
		Usage: "only list user DNs",
	},
	cli.BoolFlag{
		Name:  "temp-only, t",
		Usage: "only list temporary access keys",
	},
	cli.BoolFlag{
		Name:  "permanent-only, p",
		Usage: "only list permanent access keys/service accounts",
	},
}

var idpLdapAccesskeyListCmd = cli.Command{
	Name:         "list",
	Usage:        "list access key pairs for LDAP",
	Action:       mainIDPLdapAccesskeyList,
	Before:       setGlobalsFromContext,
	Flags:        append(idpLdapAccesskeyListFlags, globalFlags...),
	OnUsageError: onUsageError,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  TODO: add examples
	`,
}

type LDAPUsersList struct {
	Status string               `json:"status"`
	Result []LDAPUserAccessKeys `json:"result"`
}

type LDAPUserAccessKeys struct {
	DN                  string                      `json:"dn"`
	TempAccessKeys      []madmin.ServiceAccountInfo `json:"tempAccessKeys,omitempty"`
	PermanentAccessKeys []madmin.ServiceAccountInfo `json:"permanentAccessKeys,omitempty"`
}

func (m LDAPUsersList) String() string {
	return fmt.Sprintf("TODO: make string, use --json for now")
}

func (m LDAPUsersList) JSON() string {
	jsonMessageBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(jsonMessageBytes)
}

func mainIDPLdapAccesskeyList(ctx *cli.Context) error {
	if len(ctx.Args()) != 1 {
		showCommandHelpAndExit(ctx, 1) // last argument is exit code
	}

	usersOnly := ctx.Bool("users")
	tempOnly := ctx.Bool("temp-only")
	permanentOnly := ctx.Bool("permanent-only")

	if (usersOnly && permanentOnly) || (usersOnly && tempOnly) || (permanentOnly && tempOnly) {
		e := errors.New("only one of --users, --temp-only, or --permanent-only can be specified")
		fatalIf(probe.NewError(e), "Invalid flags.")
	}

	args := ctx.Args()
	aliasedURL := args.Get(0)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	// Assume admin access, change to user if ListUsers fails
	users, e := client.ListUsers(globalContext)
	if e != nil {
		if e.Error() == "Access Denied." {
			// If user does not have ListUsers permission, only get current user's access keys
			users = make(map[string]madmin.UserInfo)
			users[""] = madmin.UserInfo{}
		} else {
			fatalIf(probe.NewError(e), "Unable to retrieve users.")
		}
	}
	var accessKeyList []LDAPUserAccessKeys

	for dn := range users {
		if !usersOnly {
			accessKeys, _ := client.ListServiceAccounts(globalContext, dn)

			var tempAccessKeys []madmin.ServiceAccountInfo
			var permanentAccessKeys []madmin.ServiceAccountInfo

			for _, accessKey := range accessKeys.Accounts {
				if accessKey.Expiration.Unix() == 0 {
					permanentAccessKeys = append(permanentAccessKeys, accessKey)
				} else {
					tempAccessKeys = append(tempAccessKeys, accessKey)
				}
			}

			// if dn is blank, it means we are listing the current user's access keys
			if dn == "" {
				name, e := client.AccountInfo(globalContext, madmin.AccountOpts{})
				fatalIf(probe.NewError(e), "Unable to retrieve account name.")
				dn = name.AccountName
			}

			userAccessKeys := LDAPUserAccessKeys{
				DN: dn,
			}
			if !tempOnly {
				userAccessKeys.PermanentAccessKeys = permanentAccessKeys
			}
			if !permanentOnly {
				userAccessKeys.TempAccessKeys = tempAccessKeys
			}

			accessKeyList = append(accessKeyList, userAccessKeys)
		} else {
			// if dn is blank, it means we are listing the current user's access keys
			if dn == "" {
				name, e := client.AccountInfo(globalContext, madmin.AccountOpts{})
				fatalIf(probe.NewError(e), "Unable to retrieve account name.")
				dn = name.AccountName
			}

			accessKeyList = append(accessKeyList, LDAPUserAccessKeys{
				DN: dn,
			})
		}
	}

	m := LDAPUsersList{
		Status: "success",
		Result: accessKeyList,
	}

	printMsg(m)

	return nil
}

var idpLdapAccesskeyDeleteCmd = cli.Command{
	Name:         "delete",
	Usage:        "delete access key pairs for LDAP",
	Action:       mainIDPLdapAccesskeyDelete,
	Before:       setGlobalsFromContext,
	Flags:        globalFlags,
	OnUsageError: onUsageError,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] TARGET ACCESSKEY

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  TODO: add examples
	`,
}

type LDAPDeleteMsg struct {
	Status    string `json:"status"`
	AccessKey string `json:"accessKey"`
}

func (m LDAPDeleteMsg) String() string {
	return fmt.Sprintf("Successfully deleted access key %s", m.AccessKey)
}

func (m LDAPDeleteMsg) JSON() string {
	jsonMessageBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(jsonMessageBytes)
}

func mainIDPLdapAccesskeyDelete(ctx *cli.Context) error {
	if len(ctx.Args()) != 2 {
		showCommandHelpAndExit(ctx, 1) // last argument is exit code
	}

	args := ctx.Args()
	aliasedURL := args.Get(0)
	accessKey := args.Get(1)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	e := client.DeleteServiceAccount(globalContext, accessKey)
	fatalIf(probe.NewError(e), "Unable to delete service account.")

	m := credentialsMessage{}

	printMsg(m)

	return nil
}

var idpLdapAccesskeyCreateFlags = []cli.Flag{
	cli.DurationFlag{
		Name:   "expiration, e",
		Usage:  "expiration for temporary access keys",
		Hidden: true,
	},
}

var idpLdapAccesskeyCreateCmd = cli.Command{
	Name:         "create",
	Usage:        "create access key pairs for LDAP",
	Action:       mainIDPLdapAccesskeyCreate,
	Before:       setGlobalsFromContext,
	Flags:        append(idpLdapAccesskeyCreateFlags, globalFlags...),
	OnUsageError: onUsageError,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] TARGET

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  TODO: add examples	
	`,
}

type credentialsMessage struct {
	Status       string    `json:"status,omitempty"`
	AccessKey    string    `json:"accessKey,omitempty"`
	ParentUser   string    `json:"parentUser,omitempty"`
	SecretKey    string    `json:"secretKey,omitempty"`
	SessionToken string    `json:"sessionToken,omitempty"`
	Expiration   time.Time `json:"expiration,omitempty"`
}

func (m credentialsMessage) String() string {

	accessKey := m.AccessKey
	secretKey := m.SecretKey
	sessionToken := m.SessionToken
	expiration := m.Expiration
	expirationS := expiration.Format(time.RFC3339)

	return fmt.Sprintf("TODO: clean this\nAccess Key: %s\nSecret Key: %s\nSession Token: %s\nExpiration: %s\n", accessKey, secretKey, sessionToken, expirationS)
}

func (m credentialsMessage) JSON() string {
	jsonMessageBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(jsonMessageBytes)
}

func mainIDPLdapAccesskeyCreate(ctx *cli.Context) error {
	if len(ctx.Args()) != 1 {
		showCommandHelpAndExit(ctx, 1) // last argument is exit code
	}

	args := ctx.Args()
	aliasedURL := args.Get(0)

	expVal := ctx.Duration("expiration")
	exp := time.Now().Add(expVal)

	if expVal == 0 {
		exp = time.Unix(0, 0)
	}

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	accessKey, secretKey, e := generateCredentials()
	fatalIf(probe.NewError(e), "Unable to generate credentials.")

	res, e := client.AddServiceAccount(globalContext,
		madmin.AddServiceAccountReq{
			AccessKey:  accessKey,
			SecretKey:  secretKey,
			Expiration: &exp,
		})
	fatalIf(probe.NewError(e), "Unable to add service account.")

	m := credentialsMessage{
		Status:       "success",
		AccessKey:    res.AccessKey,
		SecretKey:    res.SecretKey,
		SessionToken: res.SessionToken,
		Expiration:   res.Expiration,
	}

	printMsg(m)

	return nil
}

var idpLdapAccesskeyInfoCmd = cli.Command{
	Name:         "info",
	Usage:        "info about given access key pairs for LDAP",
	Action:       mainIDPLdapAccesskeyInfo,
	Before:       setGlobalsFromContext,
	Flags:        append(idpLdapPolicyAttachFlags, globalFlags...),
	OnUsageError: onUsageError,
	CustomHelpTemplate: `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} [FLAGS] TARGET ACCESSKEY [ACCESSKEY...]

FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}
EXAMPLES:
  TODO: add examples
	`,
}

type LdapAcesskeyInfoMessage struct {
	Status        string     `json:"status,omitempty"`
	ParentUser    string     `json:"parentUser"`
	AccountStatus string     `json:"accountStatus"`
	ImpliedPolicy bool       `json:"impliedPolicy"`
	Policy        string     `json:"policy"`
	Name          string     `json:"name,omitempty"`
	Description   string     `json:"description,omitempty"`
	Expiration    *time.Time `json:"expiration,omitempty"`
}

func (m LdapAcesskeyInfoMessage) String() string {
	return fmt.Sprintf("TODO: write this, use --json for now")
}

func (m LdapAcesskeyInfoMessage) JSON() string {
	jsonMessageBytes, e := json.MarshalIndent(m, "", " ")
	fatalIf(probe.NewError(e), "Unable to marshal into JSON.")

	return string(jsonMessageBytes)
}

func mainIDPLdapAccesskeyInfo(ctx *cli.Context) error {
	if len(ctx.Args()) < 2 {
		showCommandHelpAndExit(ctx, 1) // last argument is exit code
	}

	// TODO: add support for multiple access keys
	args := ctx.Args()
	aliasedURL := args.Get(0)
	accessKey := args.Get(1)

	// Create a new MinIO Admin Client
	client, err := newAdminClient(aliasedURL)
	fatalIf(err, "Unable to initialize admin connection.")

	res, e := client.InfoServiceAccount(globalContext, accessKey)
	fatalIf(probe.NewError(e), "Unable to add service account.")

	m := LdapAcesskeyInfoMessage{
		Status:        "success",
		ParentUser:    res.ParentUser,
		AccountStatus: res.AccountStatus,
		ImpliedPolicy: res.ImpliedPolicy,
		Policy:        res.Policy,
		Name:          res.Name,
		Description:   res.Description,
		Expiration:    res.Expiration,
	}

	printMsg(m)

	return nil
}
