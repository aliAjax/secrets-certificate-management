package cliapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/example/secrets-cert-platform/internal/cli"
)

var rootFlags struct {
	server   string
	token    string
	identity string
}

func Run() {
	root := newRootCommand()
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "scp-cli",
		Short:         "Secrets and certificate lifecycle management CLI",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&rootFlags.server, "server", "http://localhost:8080", "platform HTTP base URL")
	root.PersistentFlags().StringVar(&rootFlags.token, "token", "dev-admin-token", "admin auth token")
	root.PersistentFlags().StringVar(&rootFlags.identity, "identity", "", "identity header for policy enforcement")
	root.AddCommand(newNamespaceCommand())
	root.AddCommand(newSecretCommand())
	root.AddCommand(newLeaseCommand())
	root.AddCommand(newPolicyCommand())
	root.AddCommand(newAuditCommand())
	root.AddCommand(newPKICommand())
	root.AddCommand(newCryptoCommand())
	return root
}

func client() *cli.Client {
	return cli.NewClient(rootFlags.server, rootFlags.token, rootFlags.identity)
}

func printJSON(value interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func newNamespaceCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "namespace", Short: "Manage namespaces"}
	cmd.AddCommand(&cobra.Command{
		Use:   "create NAME",
		Short: "Create a namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			description, _ := cmd.Flags().GetString("description")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/namespaces", map[string]string{"name": args[0], "description": description}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("description", "", "namespace description")
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List namespaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/namespaces", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func newSecretCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "secret", Short: "Manage secrets and versions"}
	cmd.AddCommand(&cobra.Command{
		Use:   "put NAMESPACE PATH VALUE",
		Short: "Create or update a secret",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			secretType, _ := cmd.Flags().GetString("type")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/namespaces/"+cli.Escape(args[0])+"/secrets", map[string]string{
				"path": args[1], "type": secretType, "value": args[2],
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("type", "kv", "secret type: static, dynamic, or kv")
	cmd.AddCommand(&cobra.Command{
		Use:   "get NAMESPACE PATH",
		Short: "Read a secret",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, _ := cmd.Flags().GetInt64("version")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", secretPathURL(args[0], args[1])+versionQuery(version), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list NAMESPACE",
		Short: "List secrets in a namespace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/namespaces/"+cli.Escape(args[0])+"/secrets", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "versions NAMESPACE PATH",
		Short: "List secret versions",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/versions/"+cli.Escape(args[0])+encodePath(args[1]), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete NAMESPACE PATH [VERSION]",
		Short: "Soft delete a secret version",
		Args:  cobra.RangeArgs(2, 3),
		RunE: func(cmd *cobra.Command, args []string) error {
			version := int64(0)
			if len(args) == 3 {
				fmt.Sscanf(args[2], "%d", &version)
			}
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "DELETE", "/v1/versions/"+cli.Escape(args[0])+"/delete"+encodePath(args[1])+versionQuery(version), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "restore NAMESPACE PATH VERSION",
		Short: "Restore a soft-deleted version",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, _ := parseVersion(args[2])
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/versions/"+cli.Escape(args[0])+"/restore"+encodePath(args[1])+versionQuery(version), map[string]string{}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "destroy NAMESPACE PATH VERSION",
		Short: "Permanently destroy a version",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, _ := parseVersion(args[2])
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/versions/"+cli.Escape(args[0])+"/destroy"+encodePath(args[1])+versionQuery(version), map[string]string{}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "rollback NAMESPACE PATH VERSION",
		Short: "Roll the current secret back to a version",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			version, _ := parseVersion(args[2])
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/versions/"+cli.Escape(args[0])+"/rollback"+encodePath(args[1])+versionQuery(version), map[string]string{}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func newLeaseCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "lease", Short: "Manage dynamic secret leases"}
	cmd.AddCommand(&cobra.Command{
		Use:   "create NAMESPACE PATH",
		Short: "Create a dynamic secret lease",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, _ := cmd.Flags().GetString("ttl")
			renewable, _ := cmd.Flags().GetBool("renewable")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/leases", map[string]interface{}{
				"namespace": args[0], "path": args[1], "ttl": ttl, "renewable": renewable,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("ttl", "1h", "lease TTL")
	cmd.PersistentFlags().Bool("renewable", true, "whether lease is renewable")
	cmd.AddCommand(&cobra.Command{
		Use:   "renew ID",
		Short: "Renew a lease",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, _ := cmd.Flags().GetString("ttl")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/leases/"+cli.Escape(args[0])+"/renew", map[string]string{"ttl": ttl}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "revoke ID",
		Short: "Revoke a lease",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/leases/"+cli.Escape(args[0])+"/revoke", map[string]string{}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func newPolicyCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Manage path access policies"}
	cmd.AddCommand(&cobra.Command{
		Use:   "create NAME NAMESPACE IDENTITY PATH_PREFIX",
		Short: "Create a policy",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			capabilities, _ := cmd.Flags().GetStringSlice("capability")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/policies", map[string]interface{}{
				"name": args[0], "namespace": args[1], "identity": args[2], "path_prefix": args[3],
				"capabilities": capabilities, "conditions": map[string]string{},
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().StringSlice("capability", []string{"read"}, "allowed capabilities")
	cmd.AddCommand(&cobra.Command{
		Use:   "list NAMESPACE",
		Short: "List policies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/policies?namespace="+cli.Escape(args[0]), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete NAME",
		Short: "Delete a policy",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "DELETE", "/v1/policies/"+cli.Escape(args[0]), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func newAuditCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Inspect audit events"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List audit events",
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace, _ := cmd.Flags().GetString("namespace")
			actor, _ := cmd.Flags().GetString("actor")
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/audit?namespace="+cli.Escape(namespace)+"&actor="+cli.Escape(actor), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("namespace", "", "filter namespace")
	cmd.PersistentFlags().String("actor", "", "filter actor")
	cmd.AddCommand(&cobra.Command{
		Use:   "verify",
		Short: "Verify the tamper-evident audit chain",
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/audit/verify", nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func newPKICommand() *cobra.Command {
	cmd := &cobra.Command{Use: "pki", Short: "Manage certificate authorities and certificates"}
	cmd.AddCommand(&cobra.Command{
		Use:   "root NAME NAMESPACE COMMON_NAME",
		Short: "Create a root CA",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, _ := cmd.Flags().GetString("ttl")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/pki/cas/root", map[string]interface{}{
				"name": args[0], "namespace": args[1], "common_name": args[2], "ttl": ttl, "max_path_len": 1,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "intermediate NAME NAMESPACE PARENT COMMON_NAME",
		Short: "Create an intermediate CA",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, _ := cmd.Flags().GetString("ttl")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/pki/cas/intermediate", map[string]interface{}{
				"name": args[0], "namespace": args[1], "parent_name": args[2], "common_name": args[3], "ttl": ttl, "max_path_len": 0,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("ttl", "8760h", "certificate TTL")
	cmd.AddCommand(&cobra.Command{
		Use:   "issue CA COMMON_NAME",
		Short: "Issue a certificate",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ttl, _ := cmd.Flags().GetString("ttl")
			dns, _ := cmd.Flags().GetStringSlice("dns")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/pki/issue", map[string]interface{}{
				"ca_name": args[0], "common_name": args[1], "ttl": ttl, "dns_names": dns,
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().StringSlice("dns", []string{}, "certificate DNS names")
	cmd.AddCommand(&cobra.Command{
		Use:   "revoke SERIAL REASON",
		Short: "Revoke a certificate",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			namespace, _ := cmd.Flags().GetString("namespace")
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/pki/revoke?namespace="+cli.Escape(namespace), map[string]string{
				"serial_number": args[0], "reason": args[1],
			}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "crl CA",
		Short: "Get a CA revocation list",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := client().Do(cmd.Context(), "GET", "/v1/pki/cas/"+cli.Escape(args[0])+"/crl", nil, &out); err != nil {
				return err
			}
			fmt.Println(out["crl"])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "ocsp CA SERIAL",
		Short: "Get an OCSP response",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := client().Do(cmd.Context(), "GET", "/v1/pki/cas/"+cli.Escape(args[0])+"/ocsp/"+cli.Escape(args[1]), nil, &out); err != nil {
				return err
			}
			fmt.Println(out["ocsp_response"])
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list-cas NAMESPACE",
		Short: "List certificate authorities",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/pki/cas?namespace="+cli.Escape(args[0]), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "list-certs NAMESPACE",
		Short: "List certificates",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out []map[string]interface{}
			if err := client().Do(cmd.Context(), "GET", "/v1/pki/certificates?namespace="+cli.Escape(args[0]), nil, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.PersistentFlags().String("namespace", "", "namespace filter")
	return cmd
}

func newCryptoCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "crypto", Short: "Invoke cryptographic operations"}
	cmd.AddCommand(&cobra.Command{
		Use:   "encrypt PLAINTEXT",
		Short: "Encrypt data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/encrypt", map[string]string{"plaintext": args[0]}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "decrypt CIPHERTEXT KEY_VERSION",
		Short: "Decrypt data",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/decrypt", map[string]string{"ciphertext": args[0], "key_version": args[1]}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "sign DATA",
		Short: "Sign data",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]string
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/sign", map[string]string{"data": args[0]}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "verify DATA SIGNATURE ALGORITHM",
		Short: "Verify a signature",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			var out map[string]interface{}
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/verify", map[string]string{"data": args[0], "signature": args[1], "algorithm": args[2]}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "derive MATERIAL SALT LENGTH",
		Short: "Derive a key",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			var length int
			fmt.Sscanf(args[2], "%d", &length)
			var out map[string]string
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/derive", map[string]interface{}{"material": args[0], "salt": args[1], "length": length}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "random LENGTH",
		Short: "Generate random bytes",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var length int
			fmt.Sscanf(args[0], "%d", &length)
			var out map[string]string
			if err := client().Do(cmd.Context(), "POST", "/v1/crypto/random", map[string]int{"length": length}, &out); err != nil {
				return err
			}
			return printJSON(out)
		},
	})
	return cmd
}

func secretPathURL(namespace, path string) string {
	return "/v1/secrets/" + cli.Escape(namespace) + encodePath(path)
}

func encodePath(path string) string {
	segments := splitPath(path)
	for i, segment := range segments {
		segments[i] = cli.Escape(segment)
	}
	return joinPath(segments)
}

func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	var out []string
	start := 0
	if path[0] == '/' {
		start = 1
	}
	for i := start; i <= len(path); i++ {
		if i == len(path) || path[i] == '/' {
			if i > start {
				out = append(out, path[start:i])
			}
			start = i + 1
		}
	}
	return out
}

func joinPath(segments []string) string {
	out := ""
	for _, segment := range segments {
		out += "/" + segment
	}
	if out == "" {
		return "/"
	}
	return out
}

func versionQuery(version int64) string {
	if version <= 0 {
		return ""
	}
	return "?version=" + fmt.Sprint(version)
}

func parseVersion(value string) (int64, error) {
	var n int64
	_, err := fmt.Sscanf(value, "%d", &n)
	return n, err
}

var _ = context.Background
var _ = base64.StdEncoding
var _ = time.Now
