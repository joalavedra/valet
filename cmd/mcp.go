package cmd

import (
	"os"

	"github.com/spf13/cobra"

	vmcp "github.com/joalavedra/valet/internal/mcp"
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Run the valet MCP server over stdio",
	RunE: func(cmd *cobra.Command, args []string) error {
		addr := os.Getenv("VALET_ADDR")
		if addr == "" {
			addr = "http://127.0.0.1:14400"
		}
		b := &vmcp.HTTPBackend{Base: addr, Token: os.Getenv("VALET_AGENT_TOKEN")}
		return vmcp.Run(cmd.Context(), b)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
