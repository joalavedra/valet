package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/joalavedra/valet/internal/store"
)

var cardCaptureLabel string
var cardCaptureTTL time.Duration

var cardCaptureCmd = &cobra.Command{
	Use:   "capture",
	Short: "Create a one-time browser link for a cardholder to enter their card via VGS Collect.js",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		token := base64.RawURLEncoding.EncodeToString(b)
		expires := time.Now().Add(cardCaptureTTL)
		meta, _ := json.Marshal(map[string]string{"provider": "vgs"})
		if err := st.CreateCapture(&store.Capture{
			Token: token, Label: cardCaptureLabel,
			Metadata: string(meta), ExpiresAt: expires,
		}); err != nil {
			return err
		}
		base := os.Getenv("VALET_PUBLIC_URL")
		if base == "" {
			listen := os.Getenv("VALET_LISTEN")
			if listen == "" {
				listen = ":14400"
			}
			host := listen
			if len(host) > 0 && host[0] == ':' {
				host = "localhost" + host
			}
			base = "http://" + host
		}
		fmt.Printf("Open in the cardholder's browser: %s/capture/%s\n", base, token)
		fmt.Printf("Link expires at %s and works once.\n", expires.UTC().Format(time.RFC3339))
		return nil
	},
}

var cardCmd = &cobra.Command{Use: "card", Short: "Card operations"}

func init() {
	cardCaptureCmd.Flags().StringVar(&cardCaptureLabel, "label", "", "credential label")
	cardCaptureCmd.Flags().DurationVar(&cardCaptureTTL, "ttl", 15*time.Minute, "capture link lifetime")
	cardCaptureCmd.MarkFlagRequired("label")
	cardCmd.AddCommand(cardCaptureCmd)
	rootCmd.AddCommand(cardCmd)
}
