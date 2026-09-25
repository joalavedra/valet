// Command valet is a credential and payment broker for AI agents.
package main

import "github.com/joalavedra/valet/cmd"

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cmd.Execute(version)
}
