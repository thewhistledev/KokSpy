package disasm

import (
	"fmt"
	"sort"
	"strings"

	"github.com/thewhistledev/kokspy/internal/analysis"
	"github.com/thewhistledev/kokspy/internal/pefile"
	"github.com/thewhistledev/kokspy/internal/vendorx86/x86asm"
)

type Line struct {
	Address uint64
	Bytes   []byte
	Text    string
	Target  uint64
	Kind    string
}

func Decode(img *pefile.Image, start uint64, count int, syntax string) ([]Line, error) {
	if img.ArchName() != "x86" && img.ArchName() != "x86-64" {
		return nil, fmt.Errorf("disassembly currently supports x86/x64 PE images; detected %s", img.ArchName())
	}
	if count <= 0 {
		count = 32
	}
	if count > 10000 {
		count = 10000
	}
	va := img.NormalizeAddress(start)
	mode := 32
	if img.Is64 {
		mode = 64
	}
	out := make([]Line, 0, count)
	for len(out) < count {
		buf, err := img.BytesAtVA(va, 15)
		if err != nil {
			if len(out) > 0 {
				break
			}
			return nil, err
		}
		if len(buf) == 0 {
			break
		}
		inst, err := x86asm.Decode(buf, mode)
		if err != nil || inst.Len <= 0 {
			out = append(out, Line{Address: va, Bytes: append([]byte(nil), buf[:1]...), Text: fmt.Sprintf("db 0x%02X", buf[0])})
			va++
			continue
		}
		line := Line{Address: va, Bytes: append([]byte(nil), buf[:inst.Len]...), Text: syntaxText(inst, va, syntax)}
		line.Target, line.Kind = relativeTarget(inst, va)
		out = append(out, line)
		va += uint64(inst.Len)
	}
	return out, nil
}

func syntaxText(inst x86asm.Inst, va uint64, syntax string) string {
	switch strings.ToLower(syntax) {
	case "gnu":
		return x86asm.GNUSyntax(inst, va, nil)
	case "go":
		return x86asm.GoSyntax(inst, va, nil)
	default:
		return x86asm.IntelSyntax(inst, va, nil)
	}
}

func relativeTarget(inst x86asm.Inst, va uint64) (uint64, string) {
	for _, a := range inst.Args {
		if rel, ok := a.(x86asm.Rel); ok {
			t := uint64(int64(va) + int64(inst.Len) + int64(rel))
			op := strings.ToUpper(inst.Op.String())
			kind := "branch"
			if op == "CALL" {
				kind = "call"
			}
			return t, kind
		}
	}
	return 0, ""
}

// XRefs performs a section-bounded linear sweep over executable bytes and
// records direct relative CALL/JMP-style references. It intentionally does not
// pretend that linear sweep is perfect code discovery on x86.
func XRefs(img *pefile.Image, maxBytesPerSection int) ([]analysis.XRef, error) {
	if img.ArchName() != "x86" && img.ArchName() != "x86-64" {
		return nil, fmt.Errorf("xrefs currently support x86/x64 PE images; detected %s", img.ArchName())
	}
	mode := 32
	if img.Is64 {
		mode = 64
	}
	var out []analysis.XRef
	for _, s := range img.ExecutableSections() {
		startOff := int(s.RawOffset)
		endOff := startOff + int(s.RawSize)
		if startOff < 0 || startOff >= len(img.Raw) {
			continue
		}
		if endOff > len(img.Raw) {
			endOff = len(img.Raw)
		}
		if maxBytesPerSection > 0 && endOff-startOff > maxBytesPerSection {
			endOff = startOff + maxBytesPerSection
		}
		data := img.Raw[startOff:endOff]
		baseVA := img.ImageBase + uint64(s.VirtualAddress)
		for pos := 0; pos < len(data); {
			inst, err := x86asm.Decode(data[pos:], mode)
			if err != nil || inst.Len <= 0 {
				pos++
				continue
			}
			va := baseVA + uint64(pos)
			if to, kind := relativeTarget(inst, va); to != 0 {
				out = append(out, analysis.XRef{From: va, To: to, Kind: kind})
			}
			pos += inst.Len
		}
	}
	return out, nil
}

func FunctionCandidates(img *pefile.Image, maxBytesPerSection int) ([]uint64, error) {
	refs, err := XRefs(img, maxBytesPerSection)
	if err != nil {
		return nil, err
	}
	set := map[uint64]struct{}{img.EntryVA: {}}
	for _, x := range refs {
		if x.Kind != "call" {
			continue
		}
		if _, ok := img.VAToOffset(x.To); ok {
			set[x.To] = struct{}{}
		}
	}
	for _, x := range img.COFFSymbols() {
		set[x.Address] = struct{}{}
	}
	if ex, _ := img.Exports(); ex != nil {
		for _, x := range ex {
			set[x.Address] = struct{}{}
		}
	}
	out := make([]uint64, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}
