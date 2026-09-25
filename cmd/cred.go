package cmd

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/joalavedra/valet/internal/crypto"
	"github.com/joalavedra/valet/internal/edge/card"
	"github.com/joalavedra/valet/internal/handle"
	"github.com/joalavedra/valet/internal/store"
)

var credAddType, credAddLabel, credAddSite, credAddLast4 string
var credAddTokenize bool

var stdinReader = bufio.NewReader(os.Stdin)

func promptSecret(name string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", name)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	line, err := stdinReader.ReadString('\n')
	return strings.TrimSpace(line), err
}

var credAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a credential (secrets are read from stdin/prompt, never args)",
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
		var h handle.Handle
		switch credAddType {
		case "login", "api_key":
			h, err = handle.New("cred", credAddSite, credAddLabel)
		case "card":
			h, err = handle.New("card", "", credAddLabel)
		default:
			return fmt.Errorf("unknown --type %q", credAddType)
		}
		if err != nil {
			return err
		}
		fields := map[string]string{}
		var prompts []string
		switch credAddType {
		case "login":
			prompts = []string{"username", "password", "totp_seed"}
		case "api_key":
			prompts = []string{"key"}
		case "card":
			if credAddTokenize {
				prompts = []string{"number", "exp_month", "exp_year", "holder", "cvc (optional)"}
			} else {
				prompts = []string{"number (alias)", "exp_month", "exp_year", "holder", "cvc (optional)"}
			}
		}
		fieldName := func(prompt string) string {
			return strings.Split(prompt, " ")[0]
		}
		raw := map[string]string{}
		for _, f := range prompts {
			v, err := promptSecret(f)
			if err != nil {
				return err
			}
			if v != "" {
				raw[fieldName(f)] = v
			}
		}
		if credAddTokenize && credAddType == "card" {
			if credAddLast4 == "" && len(raw["number"]) >= 4 {
				credAddLast4 = raw["number"][len(raw["number"])-4:]
			}
			if err := tokenizeCardFields(raw); err != nil {
				return err
			}
		}
		for k, v := range raw {
			if v != "" {
				fields[k] = v
			}
			raw[k] = "" // best-effort zero of raw values
		}
		metadata := "{}"
		if credAddType == "card" {
			meta, _ := json.Marshal(map[string]string{"provider": "vgs", "last4": credAddLast4})
			metadata = string(meta)
		}
		pt, _ := json.Marshal(fields)
		ct, err := crypto.Encrypt(dek, pt)
		if err != nil {
			return err
		}
		if err := st.AddCredential(&store.Credential{
			Handle: h.String(), Type: credAddType, Site: credAddSite, Label: credAddLabel,
			Metadata: metadata, Ciphertext: ct,
		}); err != nil {
			return err
		}
		if credAddType == "card" {
			fmt.Printf("stored card://%s (alias ...%s)\n", credAddLabel, credAddLast4)
		}
		return nil
	},
}

// tokenizeCardFields replaces raw["number"]/raw["cvc"] with provider aliases
// in place. raw["number"] is the PAN going in — callers must zero it after.
func tokenizeCardFields(raw map[string]string) error {
	p, err := card.Get("vgs")
	if err != nil {
		return fmt.Errorf("card provider: %w", err)
	}
	tok, ok := p.(card.Tokenizer)
	if !ok {
		return fmt.Errorf("card provider %q does not support tokenization", p.Name())
	}
	inputs := []card.TokenizeInput{
		{Value: raw["number"], Classifiers: []string{"credit-card", "number"}, Format: "FPE_SIX_T_FOUR"},
	}
	withCVC := raw["cvc"] != ""
	if withCVC {
		inputs = append(inputs, card.TokenizeInput{
			Value: raw["cvc"], Classifiers: []string{"credit-card", "cvc"},
			Format: "NUM_LENGTH_PRESERVING", Volatile: true,
		})
	}
	aliases, err := tok.Tokenize(context.Background(), inputs)
	if err != nil {
		return err
	}
	raw["number"] = aliases[0]
	if withCVC {
		raw["cvc"] = aliases[1]
	}
	return nil
}

var credListCmd = &cobra.Command{
	Use:   "list",
	Short: "List credential handles and metadata (never secrets)",
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		creds, err := st.ListCredentials()
		if err != nil {
			return err
		}
		for _, c := range creds {
			fmt.Printf("%s\ttype=%s\tsite=%s\tlabel=%s\n", c.Handle, c.Type, c.Site, c.Label)
		}
		return nil
	},
}

var credCmd = &cobra.Command{Use: "cred", Short: "Manage credentials"}

var agentCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create an agent and print its token once",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		st, err := store.OpenSQLite(serverDB)
		if err != nil {
			return err
		}
		defer st.Close()
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err != nil {
			return err
		}
		token := "vlt_" + hex.EncodeToString(tokenBytes)
		sum := sha256.Sum256([]byte(token))
		if _, err := st.CreateAgent(args[0], hex.EncodeToString(sum[:])); err != nil {
			return err
		}
		fmt.Println(token)
		return nil
	},
}

var agentCmd = &cobra.Command{Use: "agent", Short: "Manage agents"}

func init() {
	credAddCmd.Flags().StringVar(&credAddType, "type", "", "login | api_key | card")
	credAddCmd.Flags().StringVar(&credAddLabel, "label", "", "credential label")
	credAddCmd.Flags().StringVar(&credAddSite, "site", "", "site/domain the credential is for")
	credAddCmd.Flags().StringVar(&credAddLast4, "last4", "", "last four digits (card only, recorded in metadata)")
	credAddCmd.Flags().BoolVar(&credAddTokenize, "tokenize", false, "card only: tokenize the raw PAN/CVC via the provider's Vault API (VGS_CLIENT_ID/VGS_CLIENT_SECRET) and store only the aliases")
	credAddCmd.MarkFlagRequired("type")
	credAddCmd.MarkFlagRequired("label")
	credCmd.AddCommand(credAddCmd, credListCmd)
	agentCmd.AddCommand(agentCreateCmd)
	rootCmd.AddCommand(credCmd, agentCmd)
}
