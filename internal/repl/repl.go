package repl

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/thewhistledev/kokspy/internal/analysis"
	"github.com/thewhistledev/kokspy/internal/config"
	"github.com/thewhistledev/kokspy/internal/disasm"
	"github.com/thewhistledev/kokspy/internal/pefile"
	"github.com/thewhistledev/kokspy/internal/project"
	"github.com/thewhistledev/kokspy/internal/util"
)

type Session struct {
	Img            *pefile.Image
	Annotations    map[uint64]string
	Symbols        []analysis.Symbol
	ProjectCreated string
	Config         config.Config
	ConfigPath     string
}

func New(img *pefile.Image) *Session {
	cfgPath := config.Path()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warning: could not load config:", err)
		cfg = config.Default()
	}
	s := &Session{Img: img, Annotations: map[uint64]string{}, Config: cfg, ConfigPath: cfgPath}
	s.rebuildSymbols()
	return s
}

func (s *Session) rebuildSymbols() {
	s.Symbols = []analysis.Symbol{{Name: "entry_point", Address: s.Img.EntryVA, Kind: "entry"}}
	if ex, _ := s.Img.Exports(); ex != nil {
		s.Symbols = append(s.Symbols, ex...)
	}
	s.Symbols = append(s.Symbols, s.Img.COFFSymbols()...)
}

func (s *Session) Run() {
	fmt.Printf("KokSpy interactive disassembler | %s | %s\n", s.Img.Name, s.Img.ArchName())
	fmt.Println("Type 'help' for commands. Addresses may be VA (0x140...) or RVA (0x1000).")
	in := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("kspy> ")
		if !in.Scan() {
			fmt.Println()
			return
		}
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		if !s.Exec(line) {
			return
		}
	}
}

func (s *Session) Exec(line string) bool {
	parts := splitArgs(line)
	if len(parts) == 0 {
		return true
	}
	cmd := strings.ToLower(parts[0])
	args := parts[1:]
	switch cmd {
	case "q", "quit", "exit":
		return false
	case "help", "?":
		printHelp()
	case "info":
		s.info()
	case "sections", "sec":
		s.sections()
	case "imports", "imp":
		s.imports(args)
	case "exports", "exp":
		s.exports(args)
	case "symbols", "sym":
		s.symbols(args)
	case "strings", "str":
		s.stringsCmd(args)
	case "disasm", "d":
		s.disasmCmd(args)
	case "entry":
		s.disasmCmd([]string{fmt.Sprintf("0x%X", s.Img.EntryVA), "40"})
	case "hex", "x":
		s.hexCmd(args)
	case "find", "search":
		s.findCmd(args)
	case "entropy":
		s.entropy()
	case "functions", "funcs":
		s.functionsCmd(args)
	case "config":
		s.configCmd()
	case "set":
		s.setCmd(args)
	case "xrefs":
		s.xrefsCmd(args)
	case "annotate", "ann":
		s.annotate(args)
	case "annotations", "anns":
		s.listAnnotations()
	case "save":
		s.save(args)
	case "hash":
		h, err := util.SHA256File(s.Img.Path)
		if err != nil {
			errln(err)
		} else {
			fmt.Println(h)
		}
	case "clear", "cls":
		fmt.Print("\x1b[2J\x1b[H")
	default:
		fmt.Printf("unknown command %q; try 'help'\n", cmd)
	}
	return true
}

func printHelp() {
	fmt.Print(`
Commands:
  info                          PE summary, architecture, image base, entry point
  sections | sec                section table with permissions and entropy
  imports [filter]              imported functions/libraries
  exports [filter]              exported functions
  symbols [filter]              known entry/export/COFF symbols
  strings [min] [filter]        ASCII + UTF-16LE strings (default min 5)
  disasm | d [addr] [count]     x86/x64 disassembly (default entry, 40 instructions)
  entry                         disassemble the entry point
  hex | x [addr] [length]       hex + ASCII view (default entry, 128 bytes)
  find ascii <text>             search raw image for ASCII bytes
  find hex <hexbytes>           search bytes, e.g. find hex 48 8B ?? (?? wildcard)
  entropy                       per-section entropy (packed/encrypted data often trends high)
  functions | funcs [filter]    heuristic function candidates from direct CALL targets
  xrefs [addr]                  direct CALL/JMP references; optional target filter
  annotate <addr> <text>        attach a persistent analysis comment
  annotations                   list comments
  config                        show persistent KokSpy settings
  set syntax intel|gnu|go       choose disassembly syntax and save .kcfg
  set disasm-count <1..10000>   set default instruction count
  set string-min <3..1000>      set default string minimum length
  save [file.kspy]              save analysis as a KokSpy project bundle
  hash                          SHA-256 of target
  clear | cls                   clear terminal
  quit | exit                   leave KokSpy

Address rules: values below ImageBase are treated as RVAs; larger values as VAs.
`)
}

func (s *Session) info() {
	fmt.Printf("File:        %s\n", s.Img.Path)
	fmt.Printf("Architecture: %s\n", s.Img.ArchName())
	fmt.Printf("PE class:    PE%d\n", map[bool]int{true: 64, false: 32}[s.Img.Is64])
	fmt.Printf("Image base:  0x%X\n", s.Img.ImageBase)
	fmt.Printf("Entry RVA:   0x%X\n", s.Img.EntryRVA)
	fmt.Printf("Entry VA:    0x%X\n", s.Img.EntryVA)
	fmt.Printf("Image size:  0x%X (%d bytes)\n", s.Img.SizeOfImage, s.Img.SizeOfImage)
	fmt.Printf("Sections:    %d\n", len(s.Img.Sections))
}
func perms(c uint32) string {
	var b [3]byte
	for j := range b {
		b[j] = '-'
	}
	if c&0x40000000 != 0 {
		b[0] = 'R'
	}
	if c&0x80000000 != 0 {
		b[1] = 'W'
	}
	if c&0x20000000 != 0 {
		b[2] = 'X'
	}
	return string(b[:])
}
func (s *Session) sections() {
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tRVA\tVADDR\tVSIZE\tRAW OFF\tRAW SIZE\tPERM\tENTROPY")
	for _, x := range s.Img.Sections {
		fmt.Fprintf(tw, "%s\t0x%08X\t0x%X\t0x%X\t0x%X\t0x%X\t%s\t%.3f\n", x.Name, x.VirtualAddress, s.Img.ImageBase+uint64(x.VirtualAddress), x.VirtualSize, x.RawOffset, x.RawSize, perms(x.Characteristics), x.Entropy)
	}
	tw.Flush()
}

func (s *Session) imports(args []string) {
	f := lowerArg(args, 0)
	im, err := s.Img.Imports()
	if err != nil {
		errln(err)
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MODULE\tNAME")
	for _, x := range im {
		if f != "" && !strings.Contains(strings.ToLower(x.Module+" "+x.Name), f) {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\n", x.Module, x.Name)
	}
	tw.Flush()
	fmt.Printf("%d imports total\n", len(im))
}
func (s *Session) exports(args []string) {
	f := lowerArg(args, 0)
	ex, err := s.Img.Exports()
	if err != nil {
		errln(err)
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tKIND\tNAME")
	for _, x := range ex {
		if f != "" && !strings.Contains(strings.ToLower(x.Name), f) {
			continue
		}
		fmt.Fprintf(tw, "0x%X\t%s\t%s\n", x.Address, x.Kind, x.Name)
	}
	tw.Flush()
	fmt.Printf("%d exports total\n", len(ex))
}
func (s *Session) symbols(args []string) {
	f := lowerArg(args, 0)
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ADDRESS\tKIND\tNAME")
	for _, x := range s.Symbols {
		if f != "" && !strings.Contains(strings.ToLower(x.Name), f) {
			continue
		}
		fmt.Fprintf(tw, "0x%X\t%s\t%s\n", x.Address, x.Kind, x.Name)
	}
	tw.Flush()
}

func (s *Session) stringsCmd(args []string) {
	min := s.Config.StringMinLength
	filter := ""
	if len(args) > 0 {
		if n, e := strconv.Atoi(args[0]); e == nil {
			min = n
			if len(args) > 1 {
				filter = strings.ToLower(strings.Join(args[1:], " "))
			}
		} else {
			filter = strings.ToLower(strings.Join(args, " "))
		}
	}
	hits := s.Img.Strings(min)
	shown := 0
	for _, h := range hits {
		if filter != "" && !strings.Contains(strings.ToLower(h.Value), filter) {
			continue
		}
		fmt.Printf("0x%X  %-7s  %s\n", h.Address, h.Encoding, truncate(h.Value, 180))
		shown++
		if shown >= 500 {
			fmt.Println("... output capped at 500 matches")
			break
		}
	}
	fmt.Printf("%d strings found (%d shown)\n", len(hits), shown)
}

func (s *Session) disasmCmd(args []string) {
	addr := s.Img.EntryVA
	count := s.Config.DefaultInstructionCount
	var err error
	if len(args) > 0 {
		addr, err = parseAddr(args[0])
		if err != nil {
			errln(err)
			return
		}
		addr = s.Img.NormalizeAddress(addr)
	}
	if len(args) > 1 {
		count, _ = strconv.Atoi(args[1])
	}
	lines, err := disasm.Decode(s.Img, addr, count, s.Config.Syntax)
	if err != nil {
		errln(err)
		return
	}
	for _, l := range lines {
		label := s.labelAt(l.Address)
		if label != "" {
			fmt.Printf("\n%s:\n", label)
		}
		ann := s.Annotations[l.Address]
		bs := strings.ToUpper(hex.EncodeToString(l.Bytes))
		bs = groupHex(bs)
		fmt.Printf("0x%016X  %-32s  %-38s", l.Address, bs, l.Text)
		if ann != "" {
			fmt.Printf(" ; %s", ann)
		}
		fmt.Println()
	}
}
func (s *Session) labelAt(a uint64) string {
	for _, x := range s.Symbols {
		if x.Address == a {
			return x.Name
		}
	}
	return ""
}

func (s *Session) hexCmd(args []string) {
	addr := s.Img.EntryVA
	n := 128
	var err error
	if len(args) > 0 {
		addr, err = parseAddr(args[0])
		if err != nil {
			errln(err)
			return
		}
		addr = s.Img.NormalizeAddress(addr)
	}
	if len(args) > 1 {
		n, _ = strconv.Atoi(args[1])
	}
	if n < 1 {
		n = 1
	}
	if n > 65536 {
		n = 65536
	}
	b, err := s.Img.BytesAtVA(addr, n)
	if err != nil {
		errln(err)
		return
	}
	for o := 0; o < len(b); o += 16 {
		end := o + 16
		if end > len(b) {
			end = len(b)
		}
		chunk := b[o:end]
		fmt.Printf("0x%016X  %-47s  |%s|\n", addr+uint64(o), groupHex(strings.ToUpper(hex.EncodeToString(chunk))), ascii(chunk))
	}
}

func (s *Session) findCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: find ascii <text> | find hex <bytes>")
		return
	}
	mode := strings.ToLower(args[0])
	switch mode {
	case "ascii":
		needle := []byte(strings.Join(args[1:], " "))
		s.findExact(needle)
	case "hex":
		pat, mask, err := parseHexPattern(strings.Join(args[1:], " "))
		if err != nil {
			errln(err)
			return
		}
		shown := 0
		for off := 0; off+len(pat) <= len(s.Img.Raw); off++ {
			ok := true
			for j := range pat {
				if mask[j] && s.Img.Raw[off+j] != pat[j] {
					ok = false
					break
				}
			}
			if ok {
				if va, _ := s.Img.OffsetToVA(uint64(off)); true {
					fmt.Printf("0x%X (file+0x%X)\n", va, off)
				}
				shown++
				if shown >= 100 {
					fmt.Println("... capped at 100 matches")
					break
				}
			}
		}
		fmt.Printf("%d matches shown\n", shown)
	default:
		fmt.Println("find mode must be 'ascii' or 'hex'")
	}
}
func (s *Session) findExact(n []byte) {
	if len(n) == 0 {
		return
	}
	from := 0
	shown := 0
	for {
		p := bytes.Index(s.Img.Raw[from:], n)
		if p < 0 {
			break
		}
		off := from + p
		va, _ := s.Img.OffsetToVA(uint64(off))
		fmt.Printf("0x%X (file+0x%X)\n", va, off)
		shown++
		if shown >= 100 {
			fmt.Println("... capped at 100 matches")
			break
		}
		from = off + 1
	}
	fmt.Printf("%d matches shown\n", shown)
}

func (s *Session) entropy() {
	for _, x := range s.Img.Sections {
		note := ""
		if x.Entropy >= 7.2 {
			note = "  high"
		}
		fmt.Printf("%-10s %.3f%s\n", x.Name, x.Entropy, note)
	}
}
func (s *Session) xrefsCmd(args []string) {
	var target uint64
	filter := false
	if len(args) > 0 {
		v, e := parseAddr(args[0])
		if e != nil {
			errln(e)
			return
		}
		target = s.Img.NormalizeAddress(v)
		filter = true
	}
	refs, err := disasm.XRefs(s.Img, 8*1024*1024)
	if err != nil {
		errln(err)
		return
	}
	shown := 0
	for _, x := range refs {
		if filter && x.To != target {
			continue
		}
		fmt.Printf("0x%X -> 0x%X  %s\n", x.From, x.To, x.Kind)
		shown++
		if shown >= 1000 {
			fmt.Println("... capped at 1000 references")
			break
		}
	}
	fmt.Printf("%d references shown\n", shown)
}

func (s *Session) functionsCmd(args []string) {
	filter := lowerArg(args, 0)
	items, err := disasm.FunctionCandidates(s.Img, 8*1024*1024)
	if err != nil {
		errln(err)
		return
	}
	shown := 0
	for _, a := range items {
		name := s.labelAt(a)
		if filter != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %s", a, name)), filter) {
			continue
		}
		if name == "" {
			name = "sub_" + strings.ToUpper(strconv.FormatUint(a, 16))
		}
		fmt.Printf("0x%X  %s\n", a, name)
		shown++
		if shown >= 2000 {
			fmt.Println("... capped at 2000 candidates")
			break
		}
	}
	fmt.Printf("%d function candidates (%d shown)\n", len(items), shown)
}

func (s *Session) configCmd() {
	fmt.Printf("Config file:    %s\n", s.ConfigPath)
	fmt.Printf("Syntax:         %s\n", s.Config.Syntax)
	fmt.Printf("Disasm count:   %d\n", s.Config.DefaultInstructionCount)
	fmt.Printf("String minimum: %d\n", s.Config.StringMinLength)
}

func (s *Session) setCmd(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: set syntax intel|gnu|go | set disasm-count <n> | set string-min <n>")
		return
	}
	key := strings.ToLower(args[0])
	val := strings.ToLower(args[1])
	switch key {
	case "syntax":
		if val != "intel" && val != "gnu" && val != "go" {
			fmt.Println("syntax must be intel, gnu, or go")
			return
		}
		s.Config.Syntax = val
	case "disasm-count":
		n, err := strconv.Atoi(val)
		if err != nil || n < 1 || n > 10000 {
			fmt.Println("disasm-count must be 1..10000")
			return
		}
		s.Config.DefaultInstructionCount = n
	case "string-min":
		n, err := strconv.Atoi(val)
		if err != nil || n < 3 || n > 1000 {
			fmt.Println("string-min must be 3..1000")
			return
		}
		s.Config.StringMinLength = n
	default:
		fmt.Printf("unknown setting %q\n", key)
		return
	}
	if err := config.Save(s.ConfigPath, s.Config); err != nil {
		errln(err)
		return
	}
	fmt.Printf("saved %s\n", s.ConfigPath)
}

func (s *Session) annotate(args []string) {
	if len(args) < 2 {
		fmt.Println("usage: annotate <addr> <text>")
		return
	}
	a, e := parseAddr(args[0])
	if e != nil {
		errln(e)
		return
	}
	a = s.Img.NormalizeAddress(a)
	s.Annotations[a] = strings.Join(args[1:], " ")
	fmt.Printf("annotated 0x%X\n", a)
}
func (s *Session) listAnnotations() {
	keys := make([]uint64, 0, len(s.Annotations))
	for k := range s.Annotations {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		fmt.Printf("0x%X  %s\n", k, s.Annotations[k])
	}
}
func (s *Session) save(args []string) {
	path := ""
	if len(args) > 0 {
		path = args[0]
	} else {
		base := strings.TrimSuffix(s.Img.Name, filepath.Ext(s.Img.Name))
		path = base + ".kspy"
	}
	var anns []analysis.Annotation
	for a, t := range s.Annotations {
		anns = append(anns, analysis.Annotation{Address: a, Text: t})
	}
	sort.Slice(anns, func(i, j int) bool { return anns[i].Address < anns[j].Address })
	if s.ProjectCreated == "" {
		s.ProjectCreated = time.Now().UTC().Format(time.RFC3339)
	}
	m := project.Manifest{CreatedUTC: s.ProjectCreated, TargetPath: s.Img.Path, TargetName: s.Img.Name, Architecture: s.Img.ArchName(), ImageBase: s.Img.ImageBase, EntryVA: s.Img.EntryVA}
	if err := project.Save(path, m, anns, s.Symbols); err != nil {
		errln(err)
		return
	}
	fmt.Printf("saved %s\n", path)
}

func lowerArg(a []string, i int) string {
	if len(a) <= i {
		return ""
	}
	return strings.ToLower(strings.Join(a[i:], " "))
}
func parseAddr(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 16
		s = s[2:]
	} else if strings.HasSuffix(s, "h") {
		base = 16
		s = strings.TrimSuffix(s, "h")
	}
	v, e := strconv.ParseUint(s, base, 64)
	if e != nil {
		return 0, fmt.Errorf("invalid address %q", s)
	}
	return v, nil
}
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
func ascii(b []byte) string {
	var sb strings.Builder
	for _, x := range b {
		if x >= 32 && x <= 126 {
			sb.WriteByte(x)
		} else {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
func groupHex(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			sb.WriteByte(' ')
		}
		end := i + 2
		if end > len(s) {
			end = len(s)
		}
		sb.WriteString(s[i:end])
	}
	return sb.String()
}
func errln(e error) { fmt.Fprintln(os.Stderr, "error:", e) }
func parseHexPattern(s string) ([]byte, []bool, error) {
	fields := strings.Fields(strings.ReplaceAll(s, ",", " "))
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("empty pattern")
	}
	p := make([]byte, len(fields))
	m := make([]bool, len(fields))
	for i, f := range fields {
		f = strings.TrimPrefix(strings.ToLower(f), "0x")
		if f == "??" || f == "?" {
			continue
		}
		if len(f) != 2 {
			return nil, nil, fmt.Errorf("hex byte %q must be two digits or ??", f)
		}
		v, e := strconv.ParseUint(f, 16, 8)
		if e != nil {
			return nil, nil, fmt.Errorf("invalid hex byte %q", f)
		}
		p[i] = byte(v)
		m[i] = true
	}
	return p, m, nil
}
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	quoted := false
	for _, r := range s {
		switch r {
		case '"':
			quoted = !quoted
		case ' ', '\t':
			if quoted {
				cur.WriteRune(r)
			} else if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
