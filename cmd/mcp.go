package cmd

import (
	"os"

	"github.com/spf13/cobra"

	vmcp "github.com/joalavedra/valet/internal/mcp"
)

var mcpHTTP string

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the valet MCP server over stdio (or streamable HTTP with --http)",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := os.Getenv("VALET_ADDR")
		if addr == "" {
			addr = "http://127.0.0.1:14400"
		}
		b := &vmcp.HTTPBackend{Base: addr, Token: os.Getenv("VALET_AGENT_TOKEN")}
		if mcpHTTP != "" {
			// Bearer auth is enforced when VALET_MCP_TOKEN is set; without it
			// only loopback binds are allowed (RunHTTP refuses otherwise).
			return vmcp.RunHTTP(cmd.Context(), b, mcpHTTP, os.Getenv("VALET_MCP_TOKEN"))
		}
		return vmcp.Run(cmd.Context(), b)
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpHTTP, "http", "", "serve MCP over streamable HTTP at ADDR/mcp (e.g. 127.0.0.1:14401); requires Authorization: Bearer $VALET_MCP_TOKEN when set, loopback-only otherwise")
	rootCmd.AddCommand(mcpCmd)
}
