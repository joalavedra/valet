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
		b := &vmcp.HTTPBackend{Base: "http://127.0.0.1:14400", Token: os.Getenv("VALET_AGENT_TOKEN")}
		return vmcp.Run(cmd.Context(), b)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
}
