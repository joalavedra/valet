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
			// The streamable HTTP transport has no auth of its own; only bind
			// loopback or sit behind a trusted proxy.
			return vmcp.RunHTTP(cmd.Context(), b, mcpHTTP)
		}
		return vmcp.Run(cmd.Context(), b)
	},
}

func init() {
	mcpCmd.Flags().StringVar(&mcpHTTP, "http", "", "serve MCP over streamable HTTP at ADDR/mcp (e.g. 127.0.0.1:14401); no auth — loopback/trusted proxy only")
	rootCmd.AddCommand(mcpCmd)
}
