//go:build windows

package ui

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	WS_OVERLAPPEDWINDOW = 0x00CF0000
	WS_CHILD            = 0x40000000
	WS_VISIBLE          = 0x10000000
	WS_VSCROLL          = 0x00200000
	WS_HSCROLL          = 0x00100000
	WS_TABSTOP          = 0x00010000
	WS_BORDER           = 0x00800000

	ES_LEFT          = 0x0000
	ES_MULTILINE     = 0x0004
	ES_AUTOVSCROLL   = 0x0040
	ES_AUTOHSCROLL   = 0x0080
	ES_READONLY      = 0x0800
	ES_NOHIDESEL     = 0x0100
	SS_LEFT          = 0x00000000
	BS_PUSHBUTTON    = 0x00000000
	BS_DEFPUSHBUTTON = 0x00000001

	CBS_DROPDOWNLIST = 0x0003
	CBS_HASSTRINGS   = 0x0200

	LVS_REPORT        = 0x0001
	LVS_SINGLESEL     = 0x0004
	LVS_SHOWSELALWAYS = 0x0008

	SW_HIDE        = 0
	SW_SHOW        = 5
	SW_SHOWDEFAULT = 10

	WM_CREATE         = 0x0001
	WM_DESTROY        = 0x0002
	WM_SIZE           = 0x0005
	WM_COMMAND        = 0x0111
	WM_NOTIFY         = 0x004E
	WM_CTLCOLORSTATIC = 0x0138
	WM_CTLCOLOREDIT   = 0x0133
	WM_CTLCOLORBTN    = 0x0135
	WM_DROPFILES      = 0x0233
	WM_SETFONT        = 0x0030
	WM_APP            = 0x8000
	WM_APP_RENDER     = WM_APP + 1
	WM_APP_LOAD_DONE  = WM_APP + 2

	CB_ADDSTRING  = 0x0143
	CB_GETCURSEL  = 0x0147
	CB_SETCURSEL  = 0x014E
	CBN_SELCHANGE = 1

	EM_SETSEL       = 0x00B1
	EM_SETREADONLY  = 0x00CF
	EM_SETLIMITTEXT = 0x00C5
	EM_SETCUEBANNER = 0x1501

	LVM_FIRST                    = 0x1000
	LVM_SETBKCOLOR               = LVM_FIRST + 1
	LVM_DELETEALLITEMS           = LVM_FIRST + 9
	LVM_GETNEXTITEM              = LVM_FIRST + 12
	LVM_DELETECOLUMN             = LVM_FIRST + 28
	LVM_SETTEXTCOLOR             = LVM_FIRST + 36
	LVM_SETTEXTBKCOLOR           = LVM_FIRST + 38
	LVM_SETEXTENDEDLISTVIEWSTYLE = LVM_FIRST + 54
	LVM_INSERTITEMW              = LVM_FIRST + 77
	LVM_INSERTCOLUMNW            = LVM_FIRST + 97
	LVM_GETITEMTEXTW             = LVM_FIRST + 115
	LVM_SETITEMTEXTW             = LVM_FIRST + 116

	LVCF_WIDTH    = 0x0002
	LVCF_TEXT     = 0x0004
	LVCF_SUBITEM  = 0x0008
	LVIF_TEXT     = 0x0001
	LVNI_SELECTED = 0x0002

	LVS_EX_GRIDLINES     = 0x00000001
	LVS_EX_FULLROWSELECT = 0x00000020
	LVS_EX_DOUBLEBUFFER  = 0x00010000

	NM_DBLCLK = -3

	ICC_LISTVIEW_CLASSES = 0x00000001

	OFN_OVERWRITEPROMPT = 0x00000002
	OFN_PATHMUSTEXIST   = 0x00000800
	OFN_FILEMUSTEXIST   = 0x00001000
	OFN_EXPLORER        = 0x00080000

	IDC_ARROW = 32512

	ID_NAV_OVERVIEW    = 1001
	ID_NAV_DISASM      = 1002
	ID_NAV_SECTIONS    = 1003
	ID_NAV_IMPORTS     = 1004
	ID_NAV_EXPORTS     = 1005
	ID_NAV_SYMBOLS     = 1006
	ID_NAV_STRINGS     = 1007
	ID_NAV_FUNCTIONS   = 1008
	ID_NAV_XREFS       = 1009
	ID_NAV_HEX         = 1010
	ID_NAV_ANNOTATIONS = 1011
	ID_NAV_SETTINGS    = 1012

	ID_OPEN            = 2001
	ID_SAVE            = 2002
	ID_BACK            = 2003
	ID_FORWARD         = 2004
	ID_ENTRY           = 2005
	ID_GO              = 2006
	ID_SEARCH          = 2007
	ID_SYNTAX          = 2008
	ID_ANNOTATE        = 2009
	ID_ADDR_EDIT       = 3001
	ID_SEARCH_EDIT     = 3002
	ID_OUTPUT_EDIT     = 3003
	ID_ANNOTATION_EDIT = 3004
	ID_LISTVIEW        = 3005
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	shell32  = syscall.NewLazyDLL("shell32.dll")
	dwmapi   = syscall.NewLazyDLL("dwmapi.dll")
	uxtheme  = syscall.NewLazyDLL("uxtheme.dll")
	comctl32 = syscall.NewLazyDLL("comctl32.dll")

	pRegisterClassExW      = user32.NewProc("RegisterClassExW")
	pCreateWindowExW       = user32.NewProc("CreateWindowExW")
	pDefWindowProcW        = user32.NewProc("DefWindowProcW")
	pShowWindow            = user32.NewProc("ShowWindow")
	pUpdateWindow          = user32.NewProc("UpdateWindow")
	pGetMessageW           = user32.NewProc("GetMessageW")
	pTranslateMessage      = user32.NewProc("TranslateMessage")
	pDispatchMessageW      = user32.NewProc("DispatchMessageW")
	pPostQuitMessage       = user32.NewProc("PostQuitMessage")
	pPostMessageW          = user32.NewProc("PostMessageW")
	pMoveWindow            = user32.NewProc("MoveWindow")
	pSendMessageW          = user32.NewProc("SendMessageW")
	pSetWindowTextW        = user32.NewProc("SetWindowTextW")
	pGetWindowTextW        = user32.NewProc("GetWindowTextW")
	pGetWindowTextLengthW  = user32.NewProc("GetWindowTextLengthW")
	pMessageBoxW           = user32.NewProc("MessageBoxW")
	pLoadCursorW           = user32.NewProc("LoadCursorW")
	pInvalidateRect        = user32.NewProc("InvalidateRect")
	pEnableWindow          = user32.NewProc("EnableWindow")
	pSetBkMode             = gdi32.NewProc("SetBkMode")
	pSetTextColor          = gdi32.NewProc("SetTextColor")
	pSetBkColor            = gdi32.NewProc("SetBkColor")
	pCreateSolidBrush      = gdi32.NewProc("CreateSolidBrush")
	pCreateFontW           = gdi32.NewProc("CreateFontW")
	pGetModuleHandleW      = kernel32.NewProc("GetModuleHandleW")
	pGetOpenFileNameW      = comdlg32.NewProc("GetOpenFileNameW")
	pGetSaveFileNameW      = comdlg32.NewProc("GetSaveFileNameW")
	pDragAcceptFiles       = shell32.NewProc("DragAcceptFiles")
	pDragQueryFileW        = shell32.NewProc("DragQueryFileW")
	pDragFinish            = shell32.NewProc("DragFinish")
	pDwmSetWindowAttribute = dwmapi.NewProc("DwmSetWindowAttribute")
	pSetWindowTheme        = uxtheme.NewProc("SetWindowTheme")
	pInitCommonControlsEx  = comctl32.NewProc("InitCommonControlsEx")
)

type point struct{ X, Y int32 }

type msg struct {
	Hwnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type openFileName struct {
	LStructSize       uint32
	HwndOwner         uintptr
	HInstance         uintptr
	LpstrFilter       *uint16
	LpstrCustomFilter *uint16
	NMaxCustFilter    uint32
	NFilterIndex      uint32
	LpstrFile         *uint16
	NMaxFile          uint32
	LpstrFileTitle    *uint16
	NMaxFileTitle     uint32
	LpstrInitialDir   *uint16
	LpstrTitle        *uint16
	Flags             uint32
	NFileOffset       uint16
	NFileExtension    uint16
	LpstrDefExt       *uint16
	LCustData         uintptr
	LpfnHook          uintptr
	LpTemplateName    *uint16
	PvReserved        uintptr
	DwReserved        uint32
	FlagsEx           uint32
}

type initCommonControlsEx struct {
	DwSize uint32
	DwICC  uint32
}

type nmhdr struct {
	HwndFrom uintptr
	IDFrom   uintptr
	Code     uint32
}

type lvColumn struct {
	Mask       uint32
	Fmt        int32
	Cx         int32
	PszText    *uint16
	CchTextMax int32
	ISubItem   int32
	IImage     int32
	IOrder     int32
	CxMin      int32
	CxDefault  int32
	CxIdeal    int32
}

type lvItem struct {
	Mask       uint32
	IItem      int32
	ISubItem   int32
	State      uint32
	StateMask  uint32
	PszText    *uint16
	CchTextMax int32
	IImage     int32
	LParam     uintptr
	IIndent    int32
	IGroupID   int32
	CColumns   uint32
	PuColumns  *uint32
	PiColFmt   *int32
	IGroup     int32
}

type loadResult struct {
	requestID uint64
	path      string
	model     *Model
	err       error
}

type app struct {
	hwnd        uintptr
	model       *Model
	currentView string
	currentAddr uint64
	history     []uint64
	historyPos  int

	rendering    bool
	layouting    bool
	lastLayoutW  int
	lastLayoutH  int
	loading      bool
	loadSeq      atomic.Uint64
	loadResults  chan loadResult
	shuttingDown atomic.Bool

	logo, subtitle                                      uintptr
	nav                                                 map[string]uintptr
	openBtn, saveBtn, backBtn, forwardBtn, entryBtn     uintptr
	addrEdit, goBtn, searchEdit, searchBtn, syntaxCombo uintptr
	contentTitle, outputEdit, listView                  uintptr
	annotationLabel, annotationEdit, annotationBtn      uintptr
	status                                              uintptr

	fontUI, fontUISemibold, fontMono  uintptr
	brushBG, brushPanel, brushControl uintptr
}

var active *app

var navItems = []struct {
	id         int
	key, label string
}{
	{ID_NAV_OVERVIEW, "overview", "Overview"},
	{ID_NAV_DISASM, "disassembly", "Disassembly"},
	{ID_NAV_SECTIONS, "sections", "Sections"},
	{ID_NAV_IMPORTS, "imports", "Imports"},
	{ID_NAV_EXPORTS, "exports", "Exports"},
	{ID_NAV_SYMBOLS, "symbols", "Symbols"},
	{ID_NAV_STRINGS, "strings", "Strings"},
	{ID_NAV_FUNCTIONS, "functions", "Functions"},
	{ID_NAV_XREFS, "xrefs", "XRefs"},
	{ID_NAV_HEX, "hex", "Hex View"},
	{ID_NAV_ANNOTATIONS, "annotations", "Annotations"},
	{ID_NAV_SETTINGS, "settings", "Settings"},
}

type tableColumn struct {
	name  string
	width int
}

func Run(initialPath string) error {
	// A Win32 window and its message queue belong to the OS thread that creates
	// them. Go goroutines may otherwise migrate between threads, which can leave
	// the HWND alive while GetMessage runs against another thread's queue.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	a := &app{
		model: NewModel(), currentView: "overview", nav: map[string]uintptr{}, historyPos: -1,
		loadResults: make(chan loadResult, 2),
	}
	active = a
	if err := a.create(); err != nil {
		return err
	}

	// Do not perform real rendering from WM_CREATE. Creating and painting a full
	// native control hierarchy re-entrantly during CreateWindowEx can starve the
	// message pump on some Windows builds. Show the shell first, then post the
	// initial work back through the normal queue once GetMessage is running.
	pShowWindow.Call(a.hwnd, SW_SHOWDEFAULT)
	pUpdateWindow.Call(a.hwnd)
	pPostMessageW.Call(a.hwnd, WM_APP_RENDER, 0, 0)
	if initialPath != "" {
		a.beginOpen(initialPath)
	}

	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
	a.shuttingDown.Store(true)
	a.model.Close()
	return nil
}

func (a *app) create() error {
	icc := initCommonControlsEx{DwSize: uint32(unsafe.Sizeof(initCommonControlsEx{})), DwICC: ICC_LISTVIEW_CLASSES}
	pInitCommonControlsEx.Call(uintptr(unsafe.Pointer(&icc)))

	instance, _, _ := pGetModuleHandleW.Call(0)
	cls := utf16Ptr("KokSpyMainWindow")
	cursor, _, _ := pLoadCursorW.Call(0, IDC_ARROW)
	a.brushBG = solidBrush(rgb(16, 19, 24))
	a.brushPanel = solidBrush(rgb(21, 26, 33))
	a.brushControl = solidBrush(rgb(27, 33, 43))

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		Style:         0x0002 | 0x0001,
		LpfnWndProc:   syscall.NewCallback(wndProc),
		HInstance:     instance,
		HCursor:       cursor,
		HbrBackground: a.brushBG,
		LpszClassName: cls,
	}
	atom, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 && err != syscall.Errno(0) {
		return fmt.Errorf("RegisterClassExW: %v", err)
	}

	hwnd, _, err := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(cls)),
		uintptr(unsafe.Pointer(utf16Ptr("KokSpy - PE Analysis"))),
		WS_OVERLAPPEDWINDOW,
		90, 45, 1240, 720,
		0, 0, instance, 0,
	)
	if hwnd == 0 {
		return fmt.Errorf("CreateWindowExW: %v", err)
	}
	a.hwnd = hwnd
	a.enableDarkTitlebar()
	pDragAcceptFiles.Call(hwnd, 1)
	return nil
}

func wndProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	a := active
	switch message {
	case WM_CREATE:
		if a != nil {
			a.hwnd = hwnd
			a.createControls()
			// Keep WM_CREATE cheap. Initial layout/render is posted after the
			// top-level window exists and the normal message pump is active.
		}
		return 0
	case WM_APP_RENDER:
		if a != nil {
			a.render()
		}
		return 0
	case WM_APP_LOAD_DONE:
		if a != nil {
			a.finishOpen()
		}
		return 0
	case WM_SIZE:
		if a != nil {
			w := int(uint16(lParam & 0xffff))
			h := int(uint16((lParam >> 16) & 0xffff))
			a.layout(w, h)
		}
		return 0
	case WM_COMMAND:
		if a != nil {
			a.command(int(wParam&0xffff), int((wParam>>16)&0xffff))
		}
		return 0
	case WM_NOTIFY:
		if a != nil && lParam != 0 {
			hdr := (*nmhdr)(unsafe.Pointer(lParam))
			if hdr.HwndFrom == a.listView && int32(hdr.Code) == NM_DBLCLK {
				a.listDoubleClick()
			}
		}
		return 0
	case WM_DROPFILES:
		if a != nil {
			a.dropFile(wParam)
		}
		return 0
	case WM_CTLCOLORSTATIC, WM_CTLCOLOREDIT, WM_CTLCOLORBTN:
		if a != nil {
			hdc := wParam
			pSetTextColor.Call(hdc, uintptr(rgb(232, 237, 242)))

			// Windows sends WM_CTLCOLORSTATIC for a read-only EDIT control.
			// v0.2.1 left that DC in TRANSPARENT background mode, so when the
			// native edit control scrolled it could blit old text pixels and
			// paint the new line over them. The result was the repeated/stacked
			// glyph corruption visible in Hex View. Force an opaque background
			// for the read-only output control so exposed scroll regions erase.
			if message == WM_CTLCOLORSTATIC && lParam == a.outputEdit {
				pSetBkMode.Call(hdc, 2)
				pSetBkColor.Call(hdc, uintptr(rgb(16, 19, 24)))
				return a.brushBG
			}

			if message == WM_CTLCOLOREDIT {
				pSetBkMode.Call(hdc, 2)
				pSetBkColor.Call(hdc, uintptr(rgb(27, 33, 43)))
				return a.brushControl
			}

			pSetBkMode.Call(hdc, 1)
			if message == WM_CTLCOLORBTN {
				return a.brushPanel
			}
			return a.brushBG
		}
	case WM_DESTROY:
		if a != nil {
			a.shuttingDown.Store(true)
		}
		pPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(message), wParam, lParam)
	return r
}

func (a *app) createControls() {
	a.fontUI = createFont(-15, 400, "Segoe UI")
	a.fontUISemibold = createFont(-17, 600, "Segoe UI")
	a.fontMono = createFont(-15, 400, "Consolas")

	a.logo = a.control("STATIC", "KOKSPY", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 100, 20, 0)
	a.subtitle = a.control("STATIC", "PE ANALYSIS", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 100, 20, 0)
	a.setFont(a.logo, a.fontUISemibold)
	a.setFont(a.subtitle, a.fontUI)

	for _, n := range navItems {
		h := a.control("BUTTON", n.label, WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 100, 30, n.id)
		a.nav[n.key] = h
		a.setFont(h, a.fontUI)
		darkTheme(h)
	}

	a.openBtn = a.control("BUTTON", "Open File", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_DEFPUSHBUTTON, 0, 0, 92, 32, ID_OPEN)
	a.saveBtn = a.control("BUTTON", "Save Project", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 105, 32, ID_SAVE)
	a.backBtn = a.control("BUTTON", "<", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 34, 32, ID_BACK)
	a.forwardBtn = a.control("BUTTON", ">", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 34, 32, ID_FORWARD)
	a.entryBtn = a.control("BUTTON", "Entry", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 55, 32, ID_ENTRY)
	for _, h := range []uintptr{a.openBtn, a.saveBtn, a.backBtn, a.forwardBtn, a.entryBtn} {
		a.setFont(h, a.fontUI)
		darkTheme(h)
	}

	a.addrEdit = a.control("EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_LEFT|ES_AUTOHSCROLL, 0, 0, 190, 32, ID_ADDR_EDIT)
	a.goBtn = a.control("BUTTON", "Go", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 44, 32, ID_GO)
	a.searchEdit = a.control("EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_LEFT|ES_AUTOHSCROLL, 0, 0, 350, 32, ID_SEARCH_EDIT)
	a.searchBtn = a.control("BUTTON", "Search", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 66, 32, ID_SEARCH)
	a.syntaxCombo = a.control("COMBOBOX", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|CBS_DROPDOWNLIST|CBS_HASSTRINGS, 0, 0, 96, 220, ID_SYNTAX)
	for _, h := range []uintptr{a.addrEdit, a.goBtn, a.searchEdit, a.searchBtn, a.syntaxCombo} {
		a.setFont(h, a.fontUI)
		darkTheme(h)
	}
	pSendMessageW.Call(a.addrEdit, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(utf16Ptr("Address / RVA"))))
	pSendMessageW.Call(a.searchEdit, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(utf16Ptr("Search text or hex: 48 8B ?? E8"))))
	for _, s := range []string{"Intel", "GNU", "Go"} {
		pSendMessageW.Call(a.syntaxCombo, CB_ADDSTRING, 0, uintptr(unsafe.Pointer(utf16Ptr(s))))
	}
	idx := 0
	if a.model.Config.Syntax == "gnu" {
		idx = 1
	} else if a.model.Config.Syntax == "go" {
		idx = 2
	}
	pSendMessageW.Call(a.syntaxCombo, CB_SETCURSEL, uintptr(idx), 0)

	a.contentTitle = a.control("STATIC", "WELCOME", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 200, 28, 0)
	a.setFont(a.contentTitle, a.fontUISemibold)

	a.outputEdit = a.control(
		"EDIT", "",
		WS_CHILD|WS_VISIBLE|WS_VSCROLL|WS_HSCROLL|WS_BORDER|ES_LEFT|ES_MULTILINE|ES_AUTOVSCROLL|ES_AUTOHSCROLL|ES_READONLY|ES_NOHIDESEL,
		0, 0, 500, 500, ID_OUTPUT_EDIT,
	)
	a.setFont(a.outputEdit, a.fontMono)
	pSendMessageW.Call(a.outputEdit, EM_SETLIMITTEXT, 16*1024*1024, 0)
	pSendMessageW.Call(a.outputEdit, EM_SETREADONLY, 1, 0)

	a.listView = a.control(
		"SysListView32", "",
		WS_CHILD|WS_BORDER|WS_TABSTOP|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,
		0, 0, 500, 500, ID_LISTVIEW,
	)
	a.setFont(a.listView, a.fontMono)
	darkTheme(a.listView)
	exStyle := uintptr(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER)
	pSendMessageW.Call(a.listView, LVM_SETEXTENDEDLISTVIEWSTYLE, exStyle, exStyle)
	pSendMessageW.Call(a.listView, LVM_SETBKCOLOR, 0, uintptr(rgb(16, 19, 24)))
	pSendMessageW.Call(a.listView, LVM_SETTEXTBKCOLOR, 0, uintptr(rgb(16, 19, 24)))
	pSendMessageW.Call(a.listView, LVM_SETTEXTCOLOR, 0, uintptr(rgb(232, 237, 242)))
	pShowWindow.Call(a.listView, SW_HIDE)

	a.annotationLabel = a.control("STATIC", "Annotation", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 80, 24, 0)
	a.annotationEdit = a.control("EDIT", "", WS_CHILD|WS_VISIBLE|WS_TABSTOP|WS_BORDER|ES_LEFT|ES_AUTOHSCROLL, 0, 0, 300, 32, ID_ANNOTATION_EDIT)
	a.annotationBtn = a.control("BUTTON", "Add / Update", WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON, 0, 0, 102, 32, ID_ANNOTATE)
	a.setFont(a.annotationLabel, a.fontUI)
	a.setFont(a.annotationEdit, a.fontUI)
	a.setFont(a.annotationBtn, a.fontUI)
	darkTheme(a.annotationEdit)
	darkTheme(a.annotationBtn)
	pSendMessageW.Call(a.annotationEdit, EM_SETCUEBANNER, 1, uintptr(unsafe.Pointer(utf16Ptr("Comment at the current address"))))

	a.status = a.control("STATIC", "Ready", WS_CHILD|WS_VISIBLE|SS_LEFT, 0, 0, 400, 24, 0)
	a.setFont(a.status, a.fontUI)
}

func (a *app) control(class, text string, style uintptr, x, y, w, h, id int) uintptr {
	hnd, _, _ := pCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16Ptr(class))),
		uintptr(unsafe.Pointer(utf16Ptr(text))),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		a.hwnd, uintptr(id), 0, 0,
	)
	return hnd
}

func (a *app) layout(w, h int) {
	if a.layouting {
		return
	}
	a.layouting = true
	defer func() { a.layouting = false }()

	if w <= 0 || h <= 0 {
		return
	}
	if w == a.lastLayoutW && h == a.lastLayoutH {
		return
	}
	a.lastLayoutW, a.lastLayoutH = w, h

	if w < 900 {
		w = 900
	}
	if h < 600 {
		h = 600
	}
	const sidebar = 205
	const pad = 16
	const toolbarH = 94
	const titleH = 34
	const annH = 43
	const statusH = 24

	move(a.logo, 20, 19, 160, 26)
	move(a.subtitle, 20, 47, 160, 20)
	y := 84
	for _, n := range navItems {
		move(a.nav[n.key], 16, y, sidebar-32, 32)
		y += 37
	}

	contentX := sidebar + pad
	contentW := w - contentX - pad

	row1 := 12
	x := contentX
	move(a.openBtn, x, row1, 92, 32)
	x += 100
	move(a.saveBtn, x, row1, 105, 32)
	x += 113
	move(a.backBtn, x, row1, 34, 32)
	x += 40
	move(a.forwardBtn, x, row1, 34, 32)
	x += 42
	move(a.entryBtn, x, row1, 55, 32)
	move(a.syntaxCombo, contentX+contentW-96, row1, 96, 220)

	row2 := 50
	move(a.addrEdit, contentX, row2, 190, 32)
	move(a.goBtn, contentX+195, row2, 44, 32)
	searchX := contentX + 260
	searchBtnW := 66
	searchW := contentX + contentW - searchX - searchBtnW - 5
	if searchW < 180 {
		searchW = 180
	}
	move(a.searchEdit, searchX, row2, searchW, 32)
	move(a.searchBtn, searchX+searchW+5, row2, searchBtnW, 32)

	move(a.contentTitle, contentX, toolbarH, contentW, titleH)
	workspaceY := toolbarH + titleH
	workspaceH := h - workspaceY - annH - statusH - 7
	move(a.outputEdit, contentX, workspaceY, contentW, workspaceH)
	move(a.listView, contentX, workspaceY, contentW, workspaceH)

	annY := workspaceY + workspaceH + 6
	move(a.annotationLabel, contentX, annY+6, 76, 30)
	move(a.annotationEdit, contentX+80, annY, contentW-80-108, 32)
	move(a.annotationBtn, contentX+contentW-102, annY, 102, 32)
	move(a.status, contentX, h-statusH, contentW, statusH)
}

func (a *app) command(id, notify int) {
	switch id {
	case ID_OPEN:
		a.openDialog()
	case ID_SAVE:
		a.saveProject()
	case ID_BACK:
		a.historyMove(-1)
	case ID_FORWARD:
		a.historyMove(1)
	case ID_ENTRY:
		if a.model.Img != nil {
			a.goTo(a.model.Img.EntryVA, true)
		}
	case ID_GO:
		a.goFromEdit()
	case ID_SEARCH:
		if a.model.Img != nil {
			a.currentView = "search"
			a.render()
		}
	case ID_ANNOTATE:
		a.saveAnnotation()
	case ID_SYNTAX:
		if notify == CBN_SELCHANGE {
			idx, _, _ := pSendMessageW.Call(a.syntaxCombo, CB_GETCURSEL, 0, 0)
			syn := "intel"
			if idx == 1 {
				syn = "gnu"
			} else if idx == 2 {
				syn = "go"
			}
			if err := a.model.SetSyntax(syn); err != nil {
				a.error(err.Error())
			} else {
				a.render()
			}
		}
	default:
		for _, n := range navItems {
			if id == n.id {
				if a.model.Img == nil && n.key != "overview" && n.key != "settings" {
					return
				}
				a.currentView = n.key
				if n.key == "disassembly" && a.model.Img != nil && a.currentAddr == 0 {
					a.currentAddr = a.model.Img.EntryVA
				}
				a.render()
				return
			}
		}
	}
}

func (a *app) render() {
	if a.rendering || a.hwnd == 0 {
		return
	}
	a.rendering = true
	defer func() { a.rendering = false }()

	for _, n := range navItems {
		label := "  " + n.label
		if a.currentView == n.key {
			label = "› " + n.label
		}
		setText(a.nav[n.key], label)
	}
	a.updateEnabled()

	title := "Welcome"
	text := welcomeText
	useTable := false

	if a.model.Img == nil {
		if a.currentView == "settings" {
			title = "Settings"
			text = a.model.SettingsText()
		}
		setText(a.status, "Ready   •   Open or drop a Windows EXE, DLL, or KokSpy project")
	} else {
		filter := getText(a.searchEdit)
		switch a.currentView {
		case "overview":
			title = "Overview"
			text = a.model.OverviewText()
		case "disassembly":
			title = "Disassembly"
			if a.currentAddr == 0 {
				a.currentAddr = a.model.Img.EntryVA
			}
			useTable = true
		case "sections":
			title, useTable = "Sections", true
		case "imports":
			title, useTable = "Imports", true
		case "exports":
			title, useTable = "Exports", true
		case "symbols":
			title, useTable = "Symbols", true
		case "strings":
			title, useTable = "Strings", true
		case "functions":
			title, useTable = "Functions", true
		case "xrefs":
			title, useTable = "XRefs", true
		case "hex":
			title = "Hex View"
			if a.currentAddr == 0 {
				a.currentAddr = a.model.Img.EntryVA
			}
			// Hex is rendered in the double-buffered report control rather than
			// the multiline EDIT control. Besides fixing scroll ghosting this
			// gives stable columns and address-row navigation.
			useTable = true
		case "annotations":
			title, useTable = "Annotations", true
		case "settings":
			title = "Settings"
			text = a.model.SettingsText()
		case "search":
			title = "Search Results"
			text = a.model.SearchText(filter)
		default:
			title = "Overview"
			text = a.model.OverviewText()
		}

		if a.currentAddr != 0 {
			setText(a.addrEdit, fmt.Sprintf("0x%X", a.currentAddr))
			setText(a.annotationEdit, a.model.Annotations[a.currentAddr])
		}
		peClass := "PE32"
		if a.model.Img.Is64 {
			peClass = "PE64"
		}
		setText(a.status, fmt.Sprintf(
			"%s   •   %s / %s   •   Entry 0x%X   •   %d sections   •   %d annotations",
			a.model.Img.Name, a.model.Img.ArchName(), peClass, a.model.Img.EntryVA, len(a.model.Img.Sections), len(a.model.Annotations),
		))
	}

	setText(a.contentTitle, strings.ToUpper(title))
	if useTable {
		pShowWindow.Call(a.outputEdit, SW_HIDE)
		pShowWindow.Call(a.listView, SW_SHOW)
		a.renderTable(a.currentView, getText(a.searchEdit))
	} else {
		pShowWindow.Call(a.listView, SW_HIDE)
		pShowWindow.Call(a.outputEdit, SW_SHOW)
		setText(a.outputEdit, toCRLF(text))
		pSendMessageW.Call(a.outputEdit, EM_SETSEL, 0, 0)
	}
	pInvalidateRect.Call(a.hwnd, 0, 1)
}

func (a *app) renderTable(view, filter string) {
	f := strings.ToLower(strings.TrimSpace(filter))
	switch view {
	case "disassembly":
		a.resetList([]tableColumn{{"Address", 170}, {"Bytes", 330}, {"Instruction", 520}, {"Annotation", 360}})
		rows, err := a.model.DisassemblyRows(a.currentAddr, a.model.Config.DefaultInstructionCount)
		if err != nil {
			a.addRow([]string{"", "", err.Error(), ""})
			return
		}
		for _, r := range rows {
			ann := a.model.Annotations[r.Address]
			if f != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %X %s %s", r.Address, r.Bytes, r.Text, ann)), f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", r.Address), spacedBytes(r.Bytes), r.Text, ann})
		}
	case "sections":
		a.resetList([]tableColumn{{"Name", 110}, {"RVA", 110}, {"Virtual Address", 170}, {"Virtual Size", 120}, {"Raw Offset", 110}, {"Raw Size", 110}, {"Perm", 70}, {"Entropy", 90}})
		for _, s := range a.model.Img.Sections {
			va := a.model.Img.ImageBase + uint64(s.VirtualAddress)
			joined := strings.ToLower(fmt.Sprintf("%s %X %X", s.Name, s.VirtualAddress, va))
			if f != "" && !strings.Contains(joined, f) {
				continue
			}
			a.addRow([]string{s.Name, fmt.Sprintf("0x%08X", s.VirtualAddress), fmt.Sprintf("0x%016X", va), fmt.Sprintf("0x%X", s.VirtualSize), fmt.Sprintf("0x%X", s.RawOffset), fmt.Sprintf("0x%X", s.RawSize), perms(s.Characteristics), fmt.Sprintf("%.3f", s.Entropy)})
		}
	case "imports":
		a.resetList([]tableColumn{{"Module", 300}, {"Symbol", 760}})
		rows, err := a.model.Imports()
		if err != nil {
			a.addRow([]string{"Error", err.Error()})
			return
		}
		for _, r := range rows {
			if f != "" && !strings.Contains(strings.ToLower(r.Module+" "+r.Name), f) {
				continue
			}
			a.addRow([]string{r.Module, r.Name})
		}
	case "exports":
		a.resetList([]tableColumn{{"Address", 180}, {"Type", 160}, {"Symbol", 720}})
		rows, err := a.model.Exports()
		if err != nil {
			a.addRow([]string{"", "Error", err.Error()})
			return
		}
		for _, r := range rows {
			if f != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Kind), f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", r.Address), r.Kind, r.Name})
		}
	case "symbols":
		a.resetList([]tableColumn{{"Address", 180}, {"Type", 160}, {"Name", 720}})
		for _, r := range a.model.Symbols {
			if f != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Kind), f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", r.Address), r.Kind, r.Name})
		}
	case "strings":
		a.resetList([]tableColumn{{"Address", 180}, {"Encoding", 100}, {"Value", 900}})
		shown := 0
		for _, r := range a.model.StringRows() {
			if f != "" && !strings.Contains(strings.ToLower(r.Value), f) {
				continue
			}
			v := strings.ReplaceAll(strings.ReplaceAll(r.Value, "\r", "\\r"), "\n", "\\n")
			a.addRow([]string{fmt.Sprintf("0x%016X", r.Address), r.Encoding, v})
			shown++
			if shown >= 10000 {
				break
			}
		}
	case "functions":
		a.resetList([]tableColumn{{"Address", 180}, {"Candidate / Symbol", 820}})
		rows, err := a.model.FunctionRows()
		if err != nil {
			a.addRow([]string{"", err.Error()})
			return
		}
		for _, addr := range rows {
			name := a.model.labelAt(addr)
			if name == "" {
				name = fmt.Sprintf("sub_%X", addr)
			}
			if f != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %s", addr, name)), f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", addr), name})
		}
	case "xrefs":
		a.resetList([]tableColumn{{"From", 180}, {"To", 180}, {"Type", 120}})
		rows, err := a.model.XRefRows()
		if err != nil {
			a.addRow([]string{"", "", err.Error()})
			return
		}
		for _, r := range rows {
			joined := strings.ToLower(fmt.Sprintf("%X %X %s", r.From, r.To, r.Kind))
			if f != "" && !strings.Contains(joined, f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", r.From), fmt.Sprintf("0x%016X", r.To), r.Kind})
		}
	case "hex":
		a.resetList([]tableColumn{{"Address", 190}, {"Bytes", 570}, {"ASCII", 260}})
		rows, err := a.model.HexRows(a.currentAddr, 4096)
		if err != nil {
			a.addRow([]string{"", err.Error(), ""})
			return
		}
		for _, r := range rows {
			joined := strings.ToLower(fmt.Sprintf("%X %s %s", r.Address, r.Bytes, r.ASCII))
			if f != "" && !strings.Contains(joined, f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", r.Address), r.Bytes, r.ASCII})
		}
	case "annotations":
		a.resetList([]tableColumn{{"Address", 180}, {"Comment", 900}})
		keys := make([]uint64, 0, len(a.model.Annotations))
		for addr := range a.model.Annotations {
			keys = append(keys, addr)
		}
		sortUint64(keys)
		for _, addr := range keys {
			comment := a.model.Annotations[addr]
			if f != "" && !strings.Contains(strings.ToLower(fmt.Sprintf("%X %s", addr, comment)), f) {
				continue
			}
			a.addRow([]string{fmt.Sprintf("0x%016X", addr), comment})
		}
	}
}

func (a *app) resetList(cols []tableColumn) {
	pSendMessageW.Call(a.listView, LVM_DELETEALLITEMS, 0, 0)
	for {
		r, _, _ := pSendMessageW.Call(a.listView, LVM_DELETECOLUMN, 0, 0)
		if r == 0 {
			break
		}
	}
	for i, c := range cols {
		t := utf16Ptr(c.name)
		col := lvColumn{Mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM, Cx: int32(c.width), PszText: t, ISubItem: int32(i)}
		pSendMessageW.Call(a.listView, LVM_INSERTCOLUMNW, uintptr(i), uintptr(unsafe.Pointer(&col)))
	}
}

func (a *app) addRow(values []string) {
	if len(values) == 0 {
		return
	}
	first := utf16Ptr(values[0])
	item := lvItem{Mask: LVIF_TEXT, IItem: 0x7fffffff, ISubItem: 0, PszText: first}
	r, _, _ := pSendMessageW.Call(a.listView, LVM_INSERTITEMW, 0, uintptr(unsafe.Pointer(&item)))
	idx := int32(r)
	if idx < 0 {
		return
	}
	for j := 1; j < len(values); j++ {
		t := utf16Ptr(values[j])
		sub := lvItem{ISubItem: int32(j), PszText: t}
		pSendMessageW.Call(a.listView, LVM_SETITEMTEXTW, uintptr(idx), uintptr(unsafe.Pointer(&sub)))
	}
}

func (a *app) listDoubleClick() {
	if a.model.Img == nil {
		return
	}
	r, _, _ := pSendMessageW.Call(a.listView, LVM_GETNEXTITEM, ^uintptr(0), LVNI_SELECTED)
	idx := int(int32(r))
	if idx < 0 {
		return
	}
	col := 0
	switch a.currentView {
	case "sections":
		col = 2
	case "xrefs":
		col = 1
	case "imports":
		return
	}
	text := a.listCell(idx, col)
	addr, err := ParseAddress(text)
	if err != nil {
		return
	}
	a.goTo(a.model.NormalizeAddress(addr), true)
}

func (a *app) listCell(row, col int) string {
	buf := make([]uint16, 2048)
	item := lvItem{ISubItem: int32(col), PszText: &buf[0], CchTextMax: int32(len(buf))}
	pSendMessageW.Call(a.listView, LVM_GETITEMTEXTW, uintptr(row), uintptr(unsafe.Pointer(&item)))
	return syscall.UTF16ToString(buf)
}

func (a *app) updateEnabled() {
	has := a.model.Img != nil
	busy := a.loading
	setEnabled(a.openBtn, !busy)
	setEnabled(a.saveBtn, has && !busy)
	setEnabled(a.entryBtn, has && !busy)
	setEnabled(a.addrEdit, has && !busy)
	setEnabled(a.goBtn, has && !busy)
	setEnabled(a.searchEdit, has && !busy)
	setEnabled(a.searchBtn, has && !busy)
	setEnabled(a.annotationEdit, has && !busy)
	setEnabled(a.annotationBtn, has && !busy)
	setEnabled(a.backBtn, has && a.historyPos > 0)
	setEnabled(a.forwardBtn, has && a.historyPos >= 0 && a.historyPos < len(a.history)-1)
	for _, n := range navItems {
		enabled := !busy && (has || n.key == "overview" || n.key == "settings")
		setEnabled(a.nav[n.key], enabled)
	}
}

func (a *app) openDialog() {
	filter := multiUTF16("Windows executables (*.exe;*.dll)\x00*.exe;*.dll\x00KokSpy projects (*.kspy)\x00*.kspy\x00All files (*.*)\x00*.*\x00\x00")
	var buf [32768]uint16
	title := utf16Ptr("Open executable or KokSpy project")
	ofn := openFileName{
		LStructSize: uint32(unsafe.Sizeof(openFileName{})), HwndOwner: a.hwnd,
		LpstrFilter: &filter[0], LpstrFile: &buf[0], NMaxFile: uint32(len(buf)),
		LpstrTitle: title, Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST,
	}
	r, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r != 0 {
		a.openPath(syscall.UTF16ToString(buf[:]))
	}
}

func (a *app) openPath(path string) {
	a.beginOpen(path)
}

func (a *app) beginOpen(path string) {
	path = strings.TrimSpace(path)
	if path == "" || a.shuttingDown.Load() {
		return
	}
	req := a.loadSeq.Add(1)
	a.loading = true
	setText(a.status, "Loading and analysing "+filepath.Base(path)+" ...")
	a.updateEnabled()

	go func(requestID uint64, target string) {
		m := NewModel()
		err := m.Open(target)
		if a.shuttingDown.Load() {
			m.Close()
			return
		}
		res := loadResult{requestID: requestID, path: target, model: m, err: err}
		select {
		case a.loadResults <- res:
			pPostMessageW.Call(a.hwnd, WM_APP_LOAD_DONE, 0, 0)
		default:
			m.Close()
		}
	}(req, path)
}

func (a *app) finishOpen() {
	for {
		select {
		case res := <-a.loadResults:
			if res.requestID != a.loadSeq.Load() {
				res.model.Close()
				continue
			}
			a.loading = false
			if res.err != nil {
				res.model.Close()
				a.updateEnabled()
				a.error("Could not open file:\n\n" + res.err.Error())
				a.render()
				return
			}
			old := a.model
			a.model = res.model
			old.Close()
			a.currentAddr = a.model.Img.EntryVA
			a.history = []uint64{a.currentAddr}
			a.historyPos = 0
			a.currentView = "overview"
			setText(a.addrEdit, fmt.Sprintf("0x%X", a.currentAddr))
			setText(a.searchEdit, "")
			setText(a.annotationEdit, "")
			setText(a.hwnd, fmt.Sprintf("KokSpy - %s", filepath.Base(a.model.Img.Path)))
			a.render()
			return
		default:
			return
		}
	}
}

func (a *app) saveProject() {
	if a.model.Img == nil {
		a.error("Open an executable before saving a project.")
		return
	}
	if a.model.ProjectPath != "" {
		if err := a.model.SaveProject(a.model.ProjectPath); err != nil {
			a.error(err.Error())
		} else {
			setText(a.status, "Saved project: "+a.model.ProjectPath)
		}
		return
	}
	var buf [32768]uint16
	base := strings.TrimSuffix(a.model.Img.Name, filepath.Ext(a.model.Img.Name)) + ".kspy"
	copy(buf[:], syscall.StringToUTF16(base))
	filter := multiUTF16("KokSpy project (*.kspy)\x00*.kspy\x00\x00")
	title := utf16Ptr("Save KokSpy project")
	ofn := openFileName{
		LStructSize: uint32(unsafe.Sizeof(openFileName{})), HwndOwner: a.hwnd,
		LpstrFilter: &filter[0], LpstrFile: &buf[0], NMaxFile: uint32(len(buf)),
		LpstrTitle: title, Flags: OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST,
		LpstrDefExt: utf16Ptr("kspy"),
	}
	r, _, _ := pGetSaveFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if r == 0 {
		return
	}
	path := syscall.UTF16ToString(buf[:])
	if err := a.model.SaveProject(path); err != nil {
		a.error(err.Error())
		return
	}
	setText(a.status, "Saved project: "+a.model.ProjectPath)
}

func (a *app) goFromEdit() {
	if a.model.Img == nil {
		return
	}
	v, err := ParseAddress(getText(a.addrEdit))
	if err != nil {
		a.error("Invalid address. Use a VA such as 0x140001000 or an RVA such as 0x1000.")
		return
	}
	a.goTo(a.model.NormalizeAddress(v), true)
}

func (a *app) goTo(addr uint64, addHistory bool) {
	if a.model.Img == nil {
		return
	}
	if _, ok := a.model.Img.VAToOffset(addr); !ok {
		a.error(fmt.Sprintf("Address 0x%X is not backed by file data.", addr))
		return
	}
	a.currentAddr = addr
	a.currentView = "disassembly"
	if addHistory {
		if a.historyPos >= 0 && a.historyPos < len(a.history)-1 {
			a.history = a.history[:a.historyPos+1]
		}
		if len(a.history) == 0 || a.history[len(a.history)-1] != addr {
			a.history = append(a.history, addr)
		}
		a.historyPos = len(a.history) - 1
	}
	a.render()
}

func (a *app) historyMove(delta int) {
	next := a.historyPos + delta
	if next < 0 || next >= len(a.history) {
		return
	}
	a.historyPos = next
	a.goTo(a.history[next], false)
}

func (a *app) saveAnnotation() {
	if a.model.Img == nil {
		return
	}
	v, err := ParseAddress(getText(a.addrEdit))
	if err != nil {
		a.error("Enter a valid address before adding an annotation.")
		return
	}
	v = a.model.NormalizeAddress(v)
	if err := a.model.Annotate(v, getText(a.annotationEdit)); err != nil {
		a.error(err.Error())
		return
	}
	a.currentAddr = v
	a.render()
}

func (a *app) dropFile(hdrop uintptr) {
	var buf [32768]uint16
	n, _, _ := pDragQueryFileW.Call(hdrop, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	pDragFinish.Call(hdrop)
	if n > 0 {
		a.openPath(syscall.UTF16ToString(buf[:n]))
	}
}

func (a *app) error(text string) {
	pMessageBoxW.Call(a.hwnd, uintptr(unsafe.Pointer(utf16Ptr(text))), uintptr(unsafe.Pointer(utf16Ptr("KokSpy"))), 0x10)
}

func (a *app) setFont(hwnd, font uintptr) { pSendMessageW.Call(hwnd, WM_SETFONT, font, 1) }

func (a *app) enableDarkTitlebar() {
	v := int32(1)
	pDwmSetWindowAttribute.Call(a.hwnd, 20, uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
}

func darkTheme(hwnd uintptr) {
	pSetWindowTheme.Call(hwnd, uintptr(unsafe.Pointer(utf16Ptr("DarkMode_Explorer"))), 0)
}

func move(hwnd uintptr, x, y, w, h int) {
	if hwnd != 0 {
		pMoveWindow.Call(hwnd, uintptr(x), uintptr(y), uintptr(w), uintptr(h), 1)
	}
}

func setText(hwnd uintptr, s string) {
	if hwnd != 0 {
		pSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(utf16Ptr(s))))
	}
}

func getText(hwnd uintptr) string {
	n, _, _ := pGetWindowTextLengthW.Call(hwnd)
	if n == 0 {
		return ""
	}
	buf := make([]uint16, n+1)
	pGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), n+1)
	return syscall.UTF16ToString(buf)
}

func setEnabled(hwnd uintptr, enabled bool) {
	v := uintptr(0)
	if enabled {
		v = 1
	}
	pEnableWindow.Call(hwnd, v)
}

func utf16Ptr(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func multiUTF16(s string) []uint16 { return utf16.Encode([]rune(s)) }
func solidBrush(c uint32) uintptr  { h, _, _ := pCreateSolidBrush.Call(uintptr(c)); return h }
func rgb(r, g, b uint32) uint32    { return r | g<<8 | b<<16 }

func createFont(height int32, weight int32, name string) uintptr {
	h, _, _ := pCreateFontW.Call(uintptr(height), 0, 0, 0, uintptr(weight), 0, 0, 0, 1, 0, 0, 5, 0, uintptr(unsafe.Pointer(utf16Ptr(name))))
	return h
}

func toCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\n", "\r\n")
}

func spacedBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	const hex = "0123456789ABCDEF"
	out := make([]byte, 0, len(b)*3-1)
	for i, v := range b {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hex[v>>4], hex[v&0x0f])
	}
	return string(out)
}

func sortUint64(v []uint64) {
	for i := 1; i < len(v); i++ {
		x := v[i]
		j := i - 1
		for j >= 0 && v[j] > x {
			v[j+1] = v[j]
			j--
		}
		v[j+1] = x
	}
}
