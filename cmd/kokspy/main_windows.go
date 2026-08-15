//go:build windows

package main

import (
	"flag"
	"os"

	"github.com/thewhistledev/kokspy/internal/ui"
)

var version = "0.2.2"

func main() {
	flag.Parse()
	initial := ""
	if flag.NArg() > 0 {
		initial = flag.Arg(0)
	}
	if err := ui.Run(initial); err != nil {
		// GUI subsystem builds do not have a console. The UI reports normal
		// open/analysis errors itself; this is only a last-resort exit path.
		os.Exit(1)
	}
}
