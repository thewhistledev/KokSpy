package pefile

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thewhistledev/kokspy/internal/analysis"
)

type Section struct {
	Name            string  `json:"name"`
	VirtualAddress  uint32  `json:"virtual_address"`
	VirtualSize     uint32  `json:"virtual_size"`
	RawOffset       uint32  `json:"raw_offset"`
	RawSize         uint32  `json:"raw_size"`
	Characteristics uint32  `json:"characteristics"`
	Entropy         float64 `json:"entropy"`
}

type Image struct {
	Path        string
	Name        string
	Raw         []byte
	PE          *pe.File
	Machine     uint16
	Is64        bool
	ImageBase   uint64
	EntryRVA    uint32
	EntryVA     uint64
	SizeOfImage uint32
	Sections    []Section
}

func Open(path string) (*Image, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	pf, err := pe.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("not a valid PE executable: %w", err)
	}
	img := &Image{Path: abs, Name: filepath.Base(abs), Raw: raw, PE: pf, Machine: pf.FileHeader.Machine}
	switch oh := pf.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		img.Is64 = true
		img.ImageBase = oh.ImageBase
		img.EntryRVA = oh.AddressOfEntryPoint
		img.SizeOfImage = oh.SizeOfImage
	case *pe.OptionalHeader32:
		img.ImageBase = uint64(oh.ImageBase)
		img.EntryRVA = oh.AddressOfEntryPoint
		img.SizeOfImage = oh.SizeOfImage
	default:
		pf.Close()
		return nil, errors.New("PE has unsupported optional header")
	}
	img.EntryVA = img.ImageBase + uint64(img.EntryRVA)
	for _, s := range pf.Sections {
		data, _ := s.Data()
		img.Sections = append(img.Sections, Section{
			Name: strings.TrimRight(s.Name, "\x00"), VirtualAddress: s.VirtualAddress,
			VirtualSize: s.VirtualSize, RawOffset: s.Offset, RawSize: s.Size,
			Characteristics: s.Characteristics, Entropy: entropy(data),
		})
	}
	return img, nil
}

func (i *Image) Close() {
	if i.PE != nil {
		_ = i.PE.Close()
	}
}

func (i *Image) ArchName() string {
	switch i.Machine {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86-64"
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86"
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return "ARM64"
	default:
		return fmt.Sprintf("machine-0x%04X", i.Machine)
	}
}

func (i *Image) ExecutableSections() []Section {
	var out []Section
	for _, s := range i.Sections {
		if s.Characteristics&0x20000000 != 0 {
			out = append(out, s)
		}
	}
	return out
}

func (i *Image) RVAToOffset(rva uint64) (uint64, bool) {
	for _, s := range i.Sections {
		start := uint64(s.VirtualAddress)
		sz := uint64(s.VirtualSize)
		if uint64(s.RawSize) > sz {
			sz = uint64(s.RawSize)
		}
		if rva >= start && rva < start+sz {
			delta := rva - start
			if delta >= uint64(s.RawSize) {
				return 0, false
			}
			return uint64(s.RawOffset) + delta, true
		}
	}
	// Headers are mapped 1:1 in typical PE images.
	if rva < uint64(len(i.Raw)) {
		return rva, true
	}
	return 0, false
}

func (i *Image) VAToOffset(va uint64) (uint64, bool) {
	if va < i.ImageBase {
		return 0, false
	}
	return i.RVAToOffset(va - i.ImageBase)
}

func (i *Image) BytesAtVA(va uint64, n int) ([]byte, error) {
	off, ok := i.VAToOffset(va)
	if !ok {
		return nil, fmt.Errorf("address 0x%X is not backed by file data", va)
	}
	if n < 0 {
		return nil, errors.New("negative length")
	}
	end := off + uint64(n)
	if end > uint64(len(i.Raw)) {
		end = uint64(len(i.Raw))
	}
	return i.Raw[off:end], nil
}

func (i *Image) NormalizeAddress(v uint64) uint64 {
	if v < i.ImageBase {
		return i.ImageBase + v
	}
	return v
}

func (i *Image) Imports() ([]analysis.Symbol, error) {
	syms, err := i.PE.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	out := make([]analysis.Symbol, 0, len(syms))
	for _, s := range syms {
		name, module := s, ""
		if p := strings.LastIndex(s, ":"); p > 0 {
			name, module = s[:p], s[p+1:]
		}
		out = append(out, analysis.Symbol{Name: name, Kind: "import", Module: module})
	}
	return out, nil
}

func (i *Image) COFFSymbols() []analysis.Symbol {
	var out []analysis.Symbol
	for _, s := range i.PE.Symbols {
		if s.SectionNumber <= 0 || int(s.SectionNumber) > len(i.PE.Sections) {
			continue
		}
		sec := i.PE.Sections[s.SectionNumber-1]
		va := i.ImageBase + uint64(sec.VirtualAddress) + uint64(s.Value)
		out = append(out, analysis.Symbol{Name: s.Name, Address: va, Kind: "coff"})
	}
	return out
}

// Exports parses IMAGE_EXPORT_DIRECTORY directly because debug/pe does not expose it.
func (i *Image) Exports() ([]analysis.Symbol, error) {
	var rva, size uint32
	switch oh := i.PE.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		rva, size = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size
	case *pe.OptionalHeader32:
		rva, size = oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, oh.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].Size
	}
	if rva == 0 || size == 0 {
		return nil, nil
	}
	off, ok := i.RVAToOffset(uint64(rva))
	if !ok || off+40 > uint64(len(i.Raw)) {
		return nil, errors.New("invalid export directory")
	}
	d := i.Raw[off : off+40]
	base := binary.LittleEndian.Uint32(d[16:20])
	nFuncs := binary.LittleEndian.Uint32(d[20:24])
	nNames := binary.LittleEndian.Uint32(d[24:28])
	funcsRVA := binary.LittleEndian.Uint32(d[28:32])
	namesRVA := binary.LittleEndian.Uint32(d[32:36])
	ordsRVA := binary.LittleEndian.Uint32(d[36:40])
	funcsOff, ok1 := i.RVAToOffset(uint64(funcsRVA))
	namesOff, ok2 := i.RVAToOffset(uint64(namesRVA))
	ordsOff, ok3 := i.RVAToOffset(uint64(ordsRVA))
	if !ok1 || !ok2 || !ok3 {
		return nil, errors.New("invalid export tables")
	}
	nameByOrd := map[uint16]string{}
	for n := uint32(0); n < nNames; n++ {
		no := namesOff + uint64(n)*4
		oo := ordsOff + uint64(n)*2
		if no+4 > uint64(len(i.Raw)) || oo+2 > uint64(len(i.Raw)) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(i.Raw[no : no+4])
		ord := binary.LittleEndian.Uint16(i.Raw[oo : oo+2])
		if nameOff, ok := i.RVAToOffset(uint64(nameRVA)); ok {
			nameByOrd[ord] = readCString(i.Raw, nameOff, 4096)
		}
	}
	out := make([]analysis.Symbol, 0, nFuncs)
	for n := uint32(0); n < nFuncs; n++ {
		fo := funcsOff + uint64(n)*4
		if fo+4 > uint64(len(i.Raw)) {
			break
		}
		frva := binary.LittleEndian.Uint32(i.Raw[fo : fo+4])
		if frva == 0 {
			continue
		}
		name := nameByOrd[uint16(n)]
		if name == "" {
			name = fmt.Sprintf("ordinal_%d", base+n)
		}
		kind := "export"
		// Forwarders point back inside export directory.
		if frva >= rva && frva < rva+size {
			kind = "forwarded-export"
		}
		out = append(out, analysis.Symbol{Name: name, Address: i.ImageBase + uint64(frva), Kind: kind})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Address < out[b].Address })
	return out, nil
}

func (i *Image) Strings(min int) []analysis.StringHit {
	if min < 3 {
		min = 3
	}
	var out []analysis.StringHit
	// ASCII
	start := -1
	for p, b := range i.Raw {
		printable := b >= 0x20 && b <= 0x7e
		if printable && start < 0 {
			start = p
		}
		if (!printable || p == len(i.Raw)-1) && start >= 0 {
			end := p
			if printable && p == len(i.Raw)-1 {
				end = p + 1
			}
			if end-start >= min {
				if va, ok := i.OffsetToVA(uint64(start)); ok {
					out = append(out, analysis.StringHit{Address: va, Encoding: "ascii", Value: string(i.Raw[start:end])})
				}
			}
			start = -1
		}
	}
	// UTF-16LE simple printable subset.
	for p := 0; p+1 < len(i.Raw); {
		start := p
		chars := 0
		for p+1 < len(i.Raw) && i.Raw[p] >= 0x20 && i.Raw[p] <= 0x7e && i.Raw[p+1] == 0 {
			chars++
			p += 2
		}
		if chars >= min {
			if va, ok := i.OffsetToVA(uint64(start)); ok {
				var sb strings.Builder
				for q := start; q < start+chars*2; q += 2 {
					sb.WriteByte(i.Raw[q])
				}
				out = append(out, analysis.StringHit{Address: va, Encoding: "utf16le", Value: sb.String()})
			}
		}
		if p == start {
			p++
		}
	}
	return out
}

func (i *Image) OffsetToVA(off uint64) (uint64, bool) {
	for _, s := range i.Sections {
		if off >= uint64(s.RawOffset) && off < uint64(s.RawOffset)+uint64(s.RawSize) {
			return i.ImageBase + uint64(s.VirtualAddress) + (off - uint64(s.RawOffset)), true
		}
	}
	return i.ImageBase + off, off < uint64(len(i.Raw))
}

func entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var count [256]int
	for _, b := range data {
		count[b]++
	}
	var e float64
	for _, c := range count {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(len(data))
		e -= p * math.Log2(p)
	}
	return e
}

func readCString(b []byte, off uint64, max int) string {
	if off >= uint64(len(b)) {
		return ""
	}
	end := off
	lim := off + uint64(max)
	if lim > uint64(len(b)) {
		lim = uint64(len(b))
	}
	for end < lim && b[end] != 0 {
		end++
	}
	return string(b[off:end])
}
