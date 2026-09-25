package cmd

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/joalavedra/valet/internal/audit"
	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/browser"
	"github.com/joalavedra/valet/internal/edge/egress"
	"github.com/joalavedra/valet/internal/grant"
	"github.com/joalavedra/valet/internal/server"
	"github.com/joalavedra/valet/internal/store"
)

var serverDB string

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Start the valet HTTP API",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		dek, err := loadDEK(st)
		if err != nil {
			return err
		}
		iss := grant.NewIssuer(st, dek)
		var eg *egress.Client
		if cfg, ok := egress.FromEnv(); ok {
			eg, err = egress.New(cfg)
			if err != nil {
				return err
			}
		}
		srv := server.New(st, iss, audit.New(st), &browser.CDPFiller{}, dek, eg)
		srv.SetCDPDefault(os.Getenv("VALET_CDP_URL"))
		fmt.Println("valet server listening on :14400")
		return http.ListenAndServe(":14400", srv)
	},
}

func loadDEK(st store.Store) ([]byte, error) {
	pw := os.Getenv("VALET_MASTER_PASSWORD")
	if pw == "" {
		return nil, fmt.Errorf("VALET_MASTER_PASSWORD not set")
	}
	wrapped, err := st.Meta("wrapped_dek")
	if err == store.ErrNotFound {
		dek, err := crypto.GenerateDEK()
		if err != nil {
			return nil, err
		}
		salt, err := crypto.GenerateSalt()
		if err != nil {
			return nil, err
		}
		w, err := crypto.WrapDEK(dek, crypto.DeriveKEK(pw, salt))
		if err != nil {
			return nil, err
		}
		if err := st.SetMeta("dek_salt", base64.StdEncoding.EncodeToString(salt)); err != nil {
			return nil, err
		}
		if err := st.SetMeta("wrapped_dek", base64.StdEncoding.EncodeToString(w)); err != nil {
			return nil, err
		}
		return dek, nil
	}
	if err != nil {
		return nil, err
	}
	saltB64, err := st.Meta("dek_salt")
	if err != nil {
		return nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, err
	}
	w, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		return nil, err
	}
	return crypto.UnwrapDEK(w, crypto.DeriveKEK(pw, salt))
}

func init() {
	home, _ := os.UserHomeDir()
	rootCmd.PersistentFlags().StringVar(&serverDB, "db", filepath.Join(home, ".valet", "valet.db"), "path to SQLite database")
	rootCmd.AddCommand(serverCmd)
}
