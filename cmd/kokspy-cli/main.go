package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/thewhistledev/kokspy/internal/pefile"
	"github.com/thewhistledev/kokspy/internal/project"
	"github.com/thewhistledev/kokspy/internal/repl"
	"github.com/thewhistledev/kokspy/internal/util"
)

var version = "0.2.2"

func main() {
	var command string
	var projectOut string
	var showVersion bool
	flag.StringVar(&command, "cmd", "", "run one KokSpy command and exit (example: -cmd info)")
	flag.StringVar(&projectOut, "save", "", "save a .kspy project after analysis")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Parse()
	if showVersion {
		fmt.Printf("KokSpy %s\n", version)
		return
	}
	if flag.NArg() < 1 {
		usage()
		os.Exit(2)
	}
	input := flag.Arg(0)
	if strings.EqualFold(filepath.Ext(input), ".kspy") {
		p, err := project.Load(input)
		if err != nil {
			fatal(err)
		}
		if p.Manifest.TargetPath == "" {
			fatal(fmt.Errorf("project does not contain a target path"))
		}
		targetPath := p.Manifest.TargetPath
		if _, statErr := os.Stat(targetPath); statErr != nil && p.Manifest.TargetName != "" {
			adjacent := filepath.Join(filepath.Dir(input), p.Manifest.TargetName)
			if _, adjacentErr := os.Stat(adjacent); adjacentErr == nil {
				targetPath = adjacent
			}
		}
		img, err := pefile.Open(targetPath)
		if err != nil {
			fatal(fmt.Errorf("open project target %q: %w", targetPath, err))
		}
		defer img.Close()
		if p.Manifest.TargetSHA256 != "" {
			if h, e := util.SHA256File(img.Path); e == nil && h != p.Manifest.TargetSHA256 {
				fmt.Fprintln(os.Stderr, "warning: target SHA-256 differs from project; annotations may refer to another build")
			}
		}
		s := repl.New(img)
		s.ProjectCreated = p.Manifest.CreatedUTC
		for _, a := range p.Annotations {
			s.Annotations[a.Address] = a.Text
		}
		run(s, command, projectOut)
		return
	}
	img, err := pefile.Open(input)
	if err != nil {
		fatal(err)
	}
	defer img.Close()
	s := repl.New(img)
	run(s, command, projectOut)
}

func run(s *repl.Session, command, projectOut string) {
	if command != "" {
		s.Exec(command)
	} else {
		s.Run()
	}
	if projectOut != "" {
		s.Exec("save \"" + projectOut + "\"")
	}
}
func usage() {
	fmt.Fprintf(os.Stderr, "KokSpy %s - immediate interactive Windows PE disassembler\n\nUsage:\n  kokspy.exe <file.exe|file.dll|project.kspy>\n  kokspy.exe -cmd \"info\" <file.exe>\n  kokspy.exe -cmd \"disasm 0x1000 80\" <file.exe>\n\n", version)
	flag.PrintDefaults()
}
func fatal(err error) { fmt.Fprintln(os.Stderr, "KokSpy:", err); os.Exit(1) }
