package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/joalavedra/valet/internal/store"
	"github.com/spf13/cobra"
)

var (
	passkeyListJSON bool
	passkeyResetYes bool
)

type passkeyView struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

var passkeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List enrolled passkeys (local-only recovery: reads the DB file directly)",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		ps, err := st.ListPasskeys()
		if err != nil {
			return err
		}
		if passkeyListJSON {
			views := []passkeyView{}
			for _, p := range ps {
				views = append(views, passkeyView{ID: p.ID, Name: p.Name, CreatedAt: p.CreatedAt, LastUsedAt: p.LastUsedAt})
			}
			b, _ := json.Marshal(views)
			fmt.Println(string(b))
			return nil
		}
		for _, p := range ps {
			last := "-"
			if p.LastUsedAt != nil {
				last = p.LastUsedAt.Format(time.RFC3339)
			}
			fmt.Printf("%s\tname=%s\tcreated_at=%s\tlast_used_at=%s\n", p.ID, p.Name, p.CreatedAt.Format(time.RFC3339), last)
		}
		return nil
	},
}

var passkeyResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove all passkeys (local-only recovery for a lost authenticator or a changed passkey origin/RP ID)",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		ps, err := st.ListPasskeys()
		if err != nil {
			return err
		}
		if !passkeyResetYes {
			fmt.Printf("This removes %d passkey(s); approvals fall back to the owner token. Re-run with --yes.\n", len(ps))
			os.Exit(1)
		}
		for _, p := range ps {
			if err := st.DeletePasskey(p.ID); err != nil {
				return err
			}
		}
		fmt.Printf("removed %d passkey(s)\n", len(ps))
		return nil
	},
}

var passkeyCmd = &cobra.Command{Use: "passkey", Short: "Inspect or remove enrolled passkeys"}

func init() {
	passkeyListCmd.Flags().BoolVar(&passkeyListJSON, "json", false, "print a JSON array")
	passkeyResetCmd.Flags().BoolVar(&passkeyResetYes, "yes", false, "confirm removal of all passkeys")
	passkeyCmd.AddCommand(passkeyListCmd, passkeyResetCmd)
	rootCmd.AddCommand(passkeyCmd)
}
