package ui

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/thewhistledev/kokspy/internal/analysis"
	"github.com/thewhistledev/kokspy/internal/config"
	"github.com/thewhistledev/kokspy/internal/disasm"
	"github.com/thewhistledev/kokspy/internal/pefile"
	"github.com/thewhistledev/kokspy/internal/project"
	"github.com/thewhistledev/kokspy/internal/util"
)

type Model struct {
	Img            *pefile.Image
	Annotations    map[uint64]string
	Symbols        []analysis.Symbol
	ProjectCreated string
	ProjectPath    string
	Config         config.Config
	ConfigPath     string

	imports   []analysis.Symbol
	exports   []analysis.Symbol
	strings   []analysis.StringHit
	xrefs     []analysis.XRef
	functions []uint64
}

func NewModel() *Model {
	p := config.Path()
	cfg, err := config.Load(p)
	if err != nil {
		cfg = config.Default()
	}
	return &Model{Annotations: map[uint64]string{}, Config: cfg, ConfigPath: p}
}

func (m *Model) Close() {
	if m.Img != nil {
		m.Img.Close()
		m.Img = nil
	}
}

func (m *Model) Open(path string) error {
	m.Close()
	m.Annotations = map[uint64]string{}
	m.Symbols = nil
	m.ProjectCreated = ""
	m.ProjectPath = ""
	m.imports, m.exports, m.strings, m.xrefs, m.functions = nil, nil, nil, nil, nil

	target := path
	var loaded *project.Loaded
	var err error
	if strings.EqualFold(filepath.Ext(path), ".kspy") {
		loaded, err = project.Load(path)
		if err != nil {
			return err
		}
		target = loaded.Manifest.TargetPath
		if target == "" {
			return fmt.Errorf("project does not contain a target path")
		}
		if !fileExists(target) && loaded.Manifest.TargetName != "" {
			adjacent := filepath.Join(filepath.Dir(path), loaded.Manifest.TargetName)
			if fileExists(adjacent) {
				target = adjacent
			}
		}
	}

	img, err := pefile.Open(target)
	if err != nil {
		return err
	}
	m.Img = img
	m.Symbols = []analysis.Symbol{{Name: "entry_point", Address: img.EntryVA, Kind: "entry"}}
	if ex, e := img.Exports(); e == nil {
		m.exports = ex
		m.Symbols = append(m.Symbols, ex...)
	}
	m.Symbols = append(m.Symbols, img.COFFSymbols()...)

	if loaded != nil {
		m.ProjectPath = path
		m.ProjectCreated = loaded.Manifest.CreatedUTC
		for _, a := range loaded.Annotations {
			m.Annotations[a.Address] = a.Text
		}
		if loaded.Manifest.TargetSHA256 != "" {
			if h, e := util.SHA256File(img.Path); e == nil && h != loaded.Manifest.TargetSHA256 {
				// Keep opening the project; the GUI surfaces this as a status warning.
				m.ProjectPath = path
			}
		}
	}
	return nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func (m *Model) SaveProject(path string) error {
	if m.Img == nil {
		return fmt.Errorf("no executable is open")
	}
	if path == "" {
		path = m.ProjectPath
	}
	if path == "" {
		base := strings.TrimSuffix(m.Img.Name, filepath.Ext(m.Img.Name))
		path = filepath.Join(filepath.Dir(m.Img.Path), base+".kspy")
	}
	if !strings.EqualFold(filepath.Ext(path), ".kspy") {
		path += ".kspy"
	}
	var anns []analysis.Annotation
	for a, t := range m.Annotations {
		anns = append(anns, analysis.Annotation{Address: a, Text: t})
	}
	sort.Slice(anns, func(i, j int) bool { return anns[i].Address < anns[j].Address })
	if m.ProjectCreated == "" {
		m.ProjectCreated = time.Now().UTC().Format(time.RFC3339)
	}
	manifest := project.Manifest{
		CreatedUTC:   m.ProjectCreated,
		TargetPath:   m.Img.Path,
		TargetName:   m.Img.Name,
		Architecture: m.Img.ArchName(),
		ImageBase:    m.Img.ImageBase,
		EntryVA:      m.Img.EntryVA,
	}
	if err := project.Save(path, manifest, anns, m.Symbols); err != nil {
		return err
	}
	m.ProjectPath = path
	return nil
}

func (m *Model) SetSyntax(s string) error {
	s = strings.ToLower(strings.TrimSpace(s))
	if s != "intel" && s != "gnu" && s != "go" {
		return fmt.Errorf("unsupported syntax %q", s)
	}
	m.Config.Syntax = s
	return config.Save(m.ConfigPath, m.Config)
}

func (m *Model) SetInstructionCount(n int) error {
	if n < 1 || n > 10000 {
		return fmt.Errorf("instruction count must be 1..10000")
	}
	m.Config.DefaultInstructionCount = n
	return config.Save(m.ConfigPath, m.Config)
}

func (m *Model) SetStringMinimum(n int) error {
	if n < 3 || n > 1000 {
		return fmt.Errorf("string minimum must be 3..1000")
	}
	m.Config.StringMinLength = n
	m.strings = nil
	return config.Save(m.ConfigPath, m.Config)
}

func (m *Model) OverviewText() string {
	if m.Img == nil {
		return welcomeText
	}
	h, _ := util.SHA256File(m.Img.Path)
	peClass := 32
	if m.Img.Is64 {
		peClass = 64
	}
	imports, _ := m.Imports()
	exports, _ := m.Exports()
	return fmt.Sprintf(`KOKSPY  /  PE OVERVIEW

TARGET
  File              %s
  Path              %s
  SHA-256           %s

IMAGE
  Architecture      %s
  Format            PE%d
  Machine           0x%04X
  Image base        0x%X
  Entry RVA         0x%X
  Entry VA          0x%X
  Image size        0x%X  (%d bytes)

ANALYSIS
  Sections          %d
  Imports           %d
  Exports           %d
  Annotations       %d
  Syntax            %s

TIP
  Use the navigator on the left to move through the executable.
  Type a VA or RVA into the address box and press Go to disassemble immediately.
`, m.Img.Name, m.Img.Path, h, m.Img.ArchName(), peClass, m.Img.Machine,
		m.Img.ImageBase, m.Img.EntryRVA, m.Img.EntryVA, m.Img.SizeOfImage, m.Img.SizeOfImage,
		len(m.Img.Sections), len(imports), len(exports), len(m.Annotations), strings.ToUpper(m.Config.Syntax))
}

const welcomeText = `KOKSPY
Interactive PE analysis for Windows

Open a Windows executable, DLL, or KokSpy project to begin.

FEATURES
  • x86 / x86-64 disassembly
  • PE headers and section analysis
  • imports, exports and COFF symbols
  • ASCII and UTF-16 string discovery
  • function candidates and direct xrefs
  • hex view and byte/string search
  • persistent annotations and .kspy workspaces

Drop an .exe, .dll or .kspy file anywhere on this window, or use Open File.`

func perms(c uint32) string {
	b := []byte{'-', '-', '-'}
	if c&0x40000000 != 0 {
		b[0] = 'R'
	}
	if c&0x80000000 != 0 {
		b[1] = 'W'
	}
	if c&0x20000000 != 0 {
		b[2] = 'X'
	}
	return string(b)
}

func (m *Model) SectionsText(filter string) string {
	if m.Img == nil {
		return welcomeText
	}
	var b strings.Builder
	fmt.Fprintln(&b, "SECTIONS")
	fmt.Fprintln(&b, "")
	fmt.Fprintf(&b, "%-10s %-12s %-18s %-12s %-12s %-12s %-6s %-8s\n", "NAME", "RVA", "VIRTUAL ADDRESS", "VIRTUAL", "RAW OFF", "RAW SIZE", "PERM", "ENTROPY")
	fmt.Fprintln(&b, strings.Repeat("-", 104))
	f := strings.ToLower(filter)
	for _, s := range m.Img.Sections {
		row := fmt.Sprintf("%s %X %X", s.Name, s.VirtualAddress, m.Img.ImageBase+uint64(s.VirtualAddress))
		if f != "" && !strings.Contains(strings.ToLower(row), f) {
			continue
		}
		fmt.Fprintf(&b, "%-10s 0x%08X   0x%016X 0x%08X   0x%08X   0x%08X   %-6s %.3f\n",
			s.Name, s.VirtualAddress, m.Img.ImageBase+uint64(s.VirtualAddress), s.VirtualSize, s.RawOffset, s.RawSize, perms(s.Characteristics), s.Entropy)
	}
	return b.String()
}

func (m *Model) Imports() ([]analysis.Symbol, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if m.imports != nil {
		return m.imports, nil
	}
	x, err := m.Img.Imports()
	if err != nil {
		return nil, err
	}
	m.imports = x
	return x, nil
}
func (m *Model) Exports() ([]analysis.Symbol, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if m.exports != nil {
		return m.exports, nil
	}
	x, err := m.Img.Exports()
	if err != nil {
		return nil, err
	}
	m.exports = x
	return x, nil
}

func (m *Model) ImportsText(filter string) string {
	x, err := m.Imports()
	if err != nil {
		return "IMPORTS\n\n" + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "IMPORTS  (%d total)\n\n", len(x))
	fmt.Fprintf(&b, "%-34s %s\n%s\n", "MODULE", "SYMBOL", strings.Repeat("-", 100))
	f := strings.ToLower(filter)
	shown := 0
	for _, s := range x {
		if f != "" && !strings.Contains(strings.ToLower(s.Module+" "+s.Name), f) {
			continue
		}
		fmt.Fprintf(&b, "%-34s %s\n", s.Module, s.Name)
		shown++
		if shown >= 10000 {
			fmt.Fprintln(&b, "\n... view capped at 10,000 rows")
			break
		}
	}
	return b.String()
}

func (m *Model) ExportsText(filter string) string {
	x, err := m.Exports()
	if err != nil {
		return "EXPORTS\n\n" + err.Error()
	}
	var b strings.Builder
	fmt.Fprintf(&b, "EXPORTS  (%d total)\n\n", len(x))
	fmt.Fprintf(&b, "%-20s %-20s %s\n%s\n", "ADDRESS", "TYPE", "SYMBOL", strings.Repeat("-", 100))
	f := strings.ToLower(filter)
	for _, s := range x {
		if f != "" && !strings.Contains(strings.ToLower(s.Name+" "+s.Kind), f) {
			continue
		}
		fmt.Fprintf(&b, "0x%016X   %-20s %s\n", s.Address, s.Kind, s.Name)
	}
	return b.String()
}

func (m *Model) SymbolsText(filter string) string {
	if m.Img == nil {
		return welcomeText
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SYMBOLS  (%d known)\n\n", len(m.Symbols))
	fmt.Fprintf(&b, "%-20s %-18s %s\n%s\n", "ADDRESS", "TYPE", "NAME", strings.Repeat("-", 100))
	f := strings.ToLower(filter)
	for _, s := range m.Symbols {
		if f != "" && !strings.Contains(strings.ToLower(s.Name+" "+s.Kind), f) {
			continue
		}
		fmt.Fprintf(&b, "0x%016X   %-18s %s\n", s.Address, s.Kind, s.Name)
	}
	return b.String()
}

func (m *Model) StringsText(filter string) string {
	if m.Img == nil {
		return welcomeText
	}
	if m.strings == nil {
		m.strings = m.Img.Strings(m.Config.StringMinLength)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "STRINGS  (%d found, minimum length %d)\n\n", len(m.strings), m.Config.StringMinLength)
	fmt.Fprintf(&b, "%-20s %-10s %s\n%s\n", "ADDRESS", "ENCODING", "VALUE", strings.Repeat("-", 120))
	f := strings.ToLower(filter)
	shown := 0
	for _, s := range m.strings {
		if f != "" && !strings.Contains(strings.ToLower(s.Value), f) {
			continue
		}
		v := strings.ReplaceAll(strings.ReplaceAll(s.Value, "\r", "\\r"), "\n", "\\n")
		if len(v) > 220 {
			v = v[:220] + "..."
		}
		fmt.Fprintf(&b, "0x%016X   %-10s %s\n", s.Address, s.Encoding, v)
		shown++
		if shown >= 10000 {
			fmt.Fprintln(&b, "\n... view capped at 10,000 rows")
			break
		}
	}
	return b.String()
}

func (m *Model) labelAt(a uint64) string {
	for _, s := range m.Symbols {
		if s.Address == a {
			return s.Name
		}
	}
	return ""
}

func ParseAddress(s string) (uint64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("address is empty")
	}
	base := 10
	if strings.HasPrefix(s, "0x") {
		base = 16
		s = s[2:]
	} else if strings.HasSuffix(s, "h") {
		base = 16
		s = strings.TrimSuffix(s, "h")
	}
	v, err := strconv.ParseUint(s, base, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid address")
	}
	return v, nil
}

func (m *Model) NormalizeAddress(v uint64) uint64 {
	if m.Img == nil {
		return v
	}
	return m.Img.NormalizeAddress(v)
}

func (m *Model) DisassemblyText(addr uint64, count int) (string, error) {
	if m.Img == nil {
		return welcomeText, nil
	}
	if addr == 0 {
		addr = m.Img.EntryVA
	}
	addr = m.Img.NormalizeAddress(addr)
	if count <= 0 {
		count = m.Config.DefaultInstructionCount
	}
	lines, err := disasm.Decode(m.Img, addr, count, m.Config.Syntax)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "DISASSEMBLY  /  %s  /  %s syntax\n\n", m.Img.ArchName(), strings.ToUpper(m.Config.Syntax))
	fmt.Fprintf(&b, "%-20s %-46s %s\n%s\n", "ADDRESS", "BYTES", "INSTRUCTION", strings.Repeat("-", 124))
	for _, l := range lines {
		if label := m.labelAt(l.Address); label != "" {
			fmt.Fprintf(&b, "\n<%s>:\n", label)
		}
		bs := strings.ToUpper(hex.EncodeToString(l.Bytes))
		bs = groupHex(bs)
		fmt.Fprintf(&b, "0x%016X   %-46s %s", l.Address, bs, l.Text)
		if ann := m.Annotations[l.Address]; ann != "" {
			fmt.Fprintf(&b, "    ; %s", ann)
		}
		fmt.Fprintln(&b)
	}
	return b.String(), nil
}

type HexRow struct {
	Address uint64
	Bytes   string
	ASCII   string
}

// HexRows returns fixed-width rows for the native Hex View table. Using a
// report/list control instead of a multiline EDIT avoids Win32 scroll/paint
// artefacts and also makes each address independently selectable.
func (m *Model) HexRows(addr uint64, n int) ([]HexRow, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if addr == 0 {
		addr = m.Img.EntryVA
	}
	addr = m.Img.NormalizeAddress(addr)
	if n <= 0 {
		n = 2048
	}
	if n > 1<<20 {
		n = 1 << 20
	}
	data, err := m.Img.BytesAtVA(addr, n)
	if err != nil {
		return nil, err
	}
	rows := make([]HexRow, 0, (len(data)+15)/16)
	for o := 0; o < len(data); o += 16 {
		end := o + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[o:end]
		rows = append(rows, HexRow{
			Address: addr + uint64(o),
			Bytes:   groupHex(strings.ToUpper(hex.EncodeToString(chunk))),
			ASCII:   ascii(chunk),
		})
	}
	return rows, nil
}

func (m *Model) HexText(addr uint64, n int) (string, error) {
	if m.Img == nil {
		return welcomeText, nil
	}
	if addr == 0 {
		addr = m.Img.EntryVA
	}
	addr = m.Img.NormalizeAddress(addr)
	if n <= 0 {
		n = 512
	}
	if n > 1<<20 {
		n = 1 << 20
	}
	data, err := m.Img.BytesAtVA(addr, n)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "HEX VIEW  /  0x%X  /  %d bytes\n\n", addr, len(data))
	for o := 0; o < len(data); o += 16 {
		end := o + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[o:end]
		fmt.Fprintf(&b, "0x%016X   %-47s  |%s|\n", addr+uint64(o), groupHex(strings.ToUpper(hex.EncodeToString(chunk))), ascii(chunk))
	}
	return b.String(), nil
}

func (m *Model) XRefsText(filter string) string {
	if m.Img == nil {
		return welcomeText
	}
	if m.xrefs == nil {
		x, err := disasm.XRefs(m.Img, 16*1024*1024)
		if err != nil {
			return "XREFS\n\n" + err.Error()
		}
		m.xrefs = x
	}
	var target uint64
	targetFilter := false
	if v, err := ParseAddress(filter); err == nil && strings.TrimSpace(filter) != "" {
		target = m.Img.NormalizeAddress(v)
		targetFilter = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "DIRECT XREFS  (%d discovered)\n\n", len(m.xrefs))
	fmt.Fprintf(&b, "%-20s %-20s %-10s\n%s\n", "FROM", "TO", "TYPE", strings.Repeat("-", 72))
	shown := 0
	for _, x := range m.xrefs {
		if targetFilter && x.To != target && x.From != target {
			continue
		}
		fmt.Fprintf(&b, "0x%016X   0x%016X   %s\n", x.From, x.To, x.Kind)
		shown++
		if shown >= 10000 {
			fmt.Fprintln(&b, "\n... view capped at 10,000 rows")
			break
		}
	}
	return b.String()
}

func (m *Model) FunctionsText(filter string) string {
	if m.Img == nil {
		return welcomeText
	}
	if m.functions == nil {
		x, err := disasm.FunctionCandidates(m.Img, 16*1024*1024)
		if err != nil {
			return "FUNCTIONS\n\n" + err.Error()
		}
		m.functions = x
	}
	var b strings.Builder
	fmt.Fprintf(&b, "FUNCTION CANDIDATES  (%d discovered)\n\n", len(m.functions))
	fmt.Fprintf(&b, "%-20s %s\n%s\n", "ADDRESS", "NAME", strings.Repeat("-", 90))
	f := strings.ToLower(filter)
	for _, a := range m.functions {
		name := m.labelAt(a)
		if name == "" {
			name = fmt.Sprintf("sub_%X", a)
		}
		if f != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %s", a, name)), f) {
			continue
		}
		fmt.Fprintf(&b, "0x%016X   %s\n", a, name)
	}
	return b.String()
}

func (m *Model) AnnotationsText(filter string) string {
	var keys []uint64
	for a := range m.Annotations {
		keys = append(keys, a)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	var b strings.Builder
	fmt.Fprintf(&b, "ANNOTATIONS  (%d)\n\n", len(keys))
	fmt.Fprintf(&b, "%-20s %s\n%s\n", "ADDRESS", "COMMENT", strings.Repeat("-", 100))
	f := strings.ToLower(filter)
	for _, a := range keys {
		t := m.Annotations[a]
		if f != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %s", a, t)), f) {
			continue
		}
		fmt.Fprintf(&b, "0x%016X   %s\n", a, t)
	}
	if len(keys) == 0 {
		fmt.Fprintln(&b, "No annotations yet. Enter an address and comment in the annotation bar below.")
	}
	return b.String()
}

func (m *Model) Annotate(addr uint64, text string) error {
	if m.Img == nil {
		return fmt.Errorf("no file open")
	}
	addr = m.Img.NormalizeAddress(addr)
	text = strings.TrimSpace(text)
	if text == "" {
		delete(m.Annotations, addr)
		return nil
	}
	if _, ok := m.Img.VAToOffset(addr); !ok {
		return fmt.Errorf("address is not mapped by this image")
	}
	m.Annotations[addr] = text
	return nil
}

func (m *Model) SearchText(query string) string {
	if m.Img == nil {
		return welcomeText
	}
	q := strings.TrimSpace(query)
	if q == "" {
		return "SEARCH\n\nEnter text, or prefix a byte pattern with `hex:` (example: hex: 48 8B ?? E8)."
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SEARCH  /  %s\n\n", q)
	if strings.HasPrefix(strings.ToLower(q), "hex:") {
		pat, mask, err := parseHexPattern(strings.TrimSpace(q[4:]))
		if err != nil {
			return "SEARCH\n\n" + err.Error()
		}
		hits := 0
		for off := 0; off+len(pat) <= len(m.Img.Raw); off++ {
			ok := true
			for j := range pat {
				if mask[j] && m.Img.Raw[off+j] != pat[j] {
					ok = false
					break
				}
			}
			if ok {
				va, _ := m.Img.OffsetToVA(uint64(off))
				fmt.Fprintf(&b, "0x%016X   file+0x%X\n", va, off)
				hits++
				if hits >= 500 {
					fmt.Fprintln(&b, "\n... capped at 500 hits")
					break
				}
			}
		}
		fmt.Fprintf(&b, "\n%d matches shown\n", hits)
		return b.String()
	}
	needle := []byte(q)
	from, hits := 0, 0
	for {
		p := bytes.Index(m.Img.Raw[from:], needle)
		if p < 0 {
			break
		}
		off := from + p
		va, _ := m.Img.OffsetToVA(uint64(off))
		fmt.Fprintf(&b, "0x%016X   file+0x%X\n", va, off)
		hits++
		if hits >= 500 {
			fmt.Fprintln(&b, "\n... capped at 500 hits")
			break
		}
		from = off + 1
	}
	fmt.Fprintf(&b, "\n%d matches shown\n", hits)
	return b.String()
}

func (m *Model) SettingsText() string {
	return fmt.Sprintf(`SETTINGS

Disassembly syntax       %s
Default instruction rows %d
String minimum length    %d

Configuration file
  %s

Use the controls in the top bar to change syntax. Settings are stored in KokSpy's .kcfg format and persist across launches.`,
		strings.ToUpper(m.Config.Syntax), m.Config.DefaultInstructionCount, m.Config.StringMinLength, m.ConfigPath)
}

func parseHexPattern(s string) ([]byte, []bool, error) {
	fields := strings.Fields(strings.ReplaceAll(s, ",", " "))
	if len(fields) == 0 {
		return nil, nil, fmt.Errorf("empty hex pattern")
	}
	p := make([]byte, len(fields))
	mask := make([]bool, len(fields))
	for i, f := range fields {
		f = strings.TrimPrefix(strings.ToLower(f), "0x")
		if f == "??" || f == "?" {
			continue
		}
		if len(f) != 2 {
			return nil, nil, fmt.Errorf("hex byte %q must be two digits or ??", f)
		}
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid hex byte %q", f)
		}
		p[i] = byte(v)
		mask[i] = true
	}
	return p, mask, nil
}

func ascii(b []byte) string {
	var s strings.Builder
	for _, x := range b {
		if x >= 32 && x <= 126 {
			s.WriteByte(x)
		} else {
			s.WriteByte('.')
		}
	}
	return s.String()
}
func groupHex(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 2 {
		if i > 0 {
			b.WriteByte(' ')
		}
		end := i + 2
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}

// DisassemblyRows exposes decoded instructions for structured GUI views.
func (m *Model) DisassemblyRows(addr uint64, count int) ([]disasm.Line, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if addr == 0 {
		addr = m.Img.EntryVA
	}
	addr = m.Img.NormalizeAddress(addr)
	if count <= 0 {
		count = m.Config.DefaultInstructionCount
	}
	return disasm.Decode(m.Img, addr, count, m.Config.Syntax)
}

func (m *Model) StringRows() []analysis.StringHit {
	if m.Img == nil {
		return nil
	}
	if m.strings == nil {
		m.strings = m.Img.Strings(m.Config.StringMinLength)
	}
	return m.strings
}

func (m *Model) XRefRows() ([]analysis.XRef, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if m.xrefs == nil {
		x, err := disasm.XRefs(m.Img, 16*1024*1024)
		if err != nil {
			return nil, err
		}
		m.xrefs = x
	}
	return m.xrefs, nil
}

func (m *Model) FunctionRows() ([]uint64, error) {
	if m.Img == nil {
		return nil, fmt.Errorf("no file open")
	}
	if m.functions == nil {
		x, err := disasm.FunctionCandidates(m.Img, 16*1024*1024)
		if err != nil {
			return nil, err
		}
		m.functions = x
	}
	return m.functions, nil
}
