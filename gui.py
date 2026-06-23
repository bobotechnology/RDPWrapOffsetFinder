"""RDPWrap Offset Finder — GUI

A dark-themed, restrained tkinter GUI for the RDPWrap offset analysis tool.
Design: GUI Design Studio collective (Norman/Nielsen/Kare/Victor/Rams).
"""

from __future__ import annotations

import os
import queue
import re
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from termsrv import analyze_termsrv

# ── colour tokens (Susan Kare palette — dark terminal-pro) ────────────
CLR_BG         = "#1E1E1E"
CLR_WIDGET_BG  = "#252526"
CLR_SURFACE    = "#2D2D2D"
CLR_BORDER     = "#3C3C3C"
CLR_FG         = "#D4D4D4"
CLR_FG_DIM     = "#808080"
CLR_FG_DISABLED = "#5A5A5A"
CLR_ACCENT     = "#0078D4"
CLR_SUCCESS    = "#4EC9B0"
CLR_WARNING    = "#CE9178"
CLR_ERROR      = "#F44747"
CLR_SELECT_BG  = "#264F78"
CLR_PROGRESS   = "#0E639C"


def _get_default_termsrv_path() -> Path:
    sysroot = os.environ.get("SystemRoot", r"C:\Windows")
    return Path(sysroot) / "System32" / "termsrv.dll"


class RdpWrapGui:
    """Dark-themed analysis tool — single window, minimal chrome."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("RDPWrap Offset Finder")
        root.geometry("620x520")
        root.minsize(500, 530)
        root.configure(bg=CLR_BG)

        # threading
        self._queue: queue.Queue[tuple[str, str]] = queue.Queue()
        self._after_id: str | None = None
        self._cancel_event: threading.Event | None = None
        self._analysis_done: bool = False
        self._log_visible: bool = False

        self._build_ui()
        self._show_empty_state()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── UI construction ────────────────────────────────────────────────

    def _build_ui(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        wrapper = tk.Frame(self.root, bg=CLR_BG)
        wrapper.grid(row=0, column=0, sticky="nsew", padx=10, pady=(10, 8))
        wrapper.columnconfigure(0, weight=1)
        wrapper.rowconfigure(3, weight=1)  # output area grows

        # ── row 0 : config bar ──
        self._build_config_bar(wrapper)

        # ── row 1 : separator ──
        sep = tk.Frame(wrapper, height=1, bg=CLR_BORDER)
        sep.grid(row=1, column=0, sticky="ew", pady=(6, 2))
        sep.grid_propagate(False)

        # ── row 2 : status label (live progress / completion summary) ──
        self._build_status_bar(wrapper)

        # ── row 3 : output area (pure result — zero decoration) ──
        self._build_output_area(wrapper)

        # ── row 4 : dev log panel (hidden by default) ──
        self._build_log_panel(wrapper)

        # ── row 5 : action buttons ──
        self._build_action_bar(wrapper)

    def _build_config_bar(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=CLR_BG)
        bar.grid(row=0, column=0, sticky="ew")
        bar.columnconfigure(0, weight=1)

        self.path_var = tk.StringVar(value=str(_get_default_termsrv_path()))
        self.path_entry = tk.Entry(
            bar,
            textvariable=self.path_var,
            bg=CLR_WIDGET_BG,
            fg=CLR_FG,
            insertbackground=CLR_FG,
            selectbackground=CLR_SELECT_BG,
            selectforeground=CLR_FG,
            relief="flat",
            bd=5,
            font=("Segoe UI", 9),
        )
        self.path_entry.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        self.path_entry.bind("<FocusOut>", lambda _e: self._validate_path_silent())

        self.browse_btn = tk.Button(
            bar,
            text="...",
            command=self._browse_file,
            bg=CLR_SURFACE,
            fg=CLR_FG,
            activebackground=CLR_BORDER,
            activeforeground=CLR_FG,
            relief="flat",
            bd=4,
            font=("Segoe UI", 9),
            cursor="hand2",
            width=3,
        )
        self.browse_btn.grid(row=0, column=1, padx=(0, 10))

        self.mode_var = tk.StringVar(value="symbol")
        mode_sub = tk.Frame(bar, bg=CLR_BG)
        mode_sub.grid(row=0, column=2, sticky="e")

        sym_frame = tk.Frame(mode_sub, bg=CLR_BG)
        sym_frame.pack(side="left", padx=(0, 12))

        self.sym_rb = tk.Radiobutton(
            sym_frame,
            text="Symbol-based",
            variable=self.mode_var,
            value="symbol",
            bg=CLR_BG,
            fg=CLR_SUCCESS,
            selectcolor=CLR_WIDGET_BG,
            activebackground=CLR_BG,
            activeforeground=CLR_SUCCESS,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        self.sym_rb.pack(side="left")
        rec_lbl = tk.Label(
            sym_frame,
            text="REC",
            bg=CLR_SUCCESS,
            fg=CLR_BG,
            font=("Segoe UI", 7, "bold"),
            padx=4,
        )
        rec_lbl.pack(side="left", padx=(2, 0))

        nosym_frame = tk.Frame(mode_sub, bg=CLR_BG)
        nosym_frame.pack(side="left")

        self.nosym_rb = tk.Radiobutton(
            nosym_frame,
            text="No-symbol",
            variable=self.mode_var,
            value="nosymbol",
            bg=CLR_BG,
            fg=CLR_FG_DIM,
            selectcolor=CLR_WIDGET_BG,
            activebackground=CLR_BG,
            activeforeground=CLR_FG_DIM,
            font=("Segoe UI", 9),
            cursor="hand2",
        )
        self.nosym_rb.pack(side="left")
        offline_lbl = tk.Label(
            nosym_frame,
            text="OFFLINE",
            bg=CLR_WIDGET_BG,
            fg=CLR_FG_DIM,
            font=("Segoe UI", 7),
            padx=4,
        )
        offline_lbl.pack(side="left", padx=(2, 0))

    def _build_status_bar(self, parent: tk.Frame) -> None:
        """Single-line status label — replaces the original status bar."""
        self.status_label = tk.Label(
            parent,
            text="",
            bg=CLR_BG,
            fg=CLR_FG_DIM,
            font=("Segoe UI", 9),
            anchor="w",
        )
        self.status_label.grid(row=2, column=0, sticky="ew", pady=(4, 0))

    def _build_output_area(self, parent: tk.Frame) -> None:
        frame = tk.Frame(parent, bg=CLR_BG)
        frame.grid(row=3, column=0, sticky="nsew", pady=(4, 6))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        self.output_text = tk.Text(
            frame,
            wrap="none",
            font=("Consolas", 10),
            state="disabled",
            bg=CLR_WIDGET_BG,
            fg=CLR_FG,
            insertbackground=CLR_FG,
            selectbackground=CLR_SELECT_BG,
            selectforeground=CLR_FG,
            relief="flat",
            bd=6,
            padx=8,
            pady=8,
            undo=False,
            cursor="arrow",
        )
        self.output_text.grid(row=0, column=0, sticky="nsew")

        vsb = tk.Scrollbar(
            frame,
            orient="vertical",
            command=self.output_text.yview,
            bg=CLR_SURFACE,
            troughcolor=CLR_BG,
            activebackground=CLR_BORDER,
            relief="flat",
            bd=0,
            highlightthickness=0,
        )
        vsb.grid(row=0, column=1, sticky="ns")
        self.output_text.configure(yscrollcommand=vsb.set)

        # tags for colouring
        self.output_text.tag_configure("dim", foreground=CLR_FG_DIM)
        self.output_text.tag_configure("warn", foreground=CLR_WARNING)
        self.output_text.tag_configure("error", foreground=CLR_ERROR, font=("Consolas", 10, "bold"))
        self.output_text.tag_configure("clickable", foreground=CLR_ACCENT, underline=True)
        self.output_text.tag_configure("guide", foreground=CLR_FG_DIM, font=("Consolas", 10))
        self.output_text.tag_bind("clickable", "<Button-1>", self._on_click_offset)

        # Ctrl+A only — Ctrl+C uses default Text behaviour (output is clean)
        self.output_text.bind("<Control-a>", lambda _e: self._select_all())
        self.output_text.bind("<Control-A>", lambda _e: self._select_all())

    def _build_log_panel(self, parent: tk.Frame) -> None:
        """Collapsible developer log panel — hidden by default."""
        self.log_frame = tk.Frame(parent, bg=CLR_BG, height=140)
        self.log_frame.grid(row=4, column=0, sticky="nsew", pady=(0, 4))
        self.log_frame.columnconfigure(0, weight=1)
        self.log_frame.rowconfigure(0, weight=1)
        self.log_frame.grid_propagate(False)
        self.log_frame.grid_remove()  # hidden initially

        # separator line above log
        log_sep = tk.Frame(self.log_frame, height=1, bg=CLR_BORDER)
        log_sep.pack(fill="x", pady=(0, 2))

        log_text_frame = tk.Frame(self.log_frame, bg=CLR_BG)
        log_text_frame.pack(fill="both", expand=True)
        log_text_frame.columnconfigure(0, weight=1)
        log_text_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_text_frame,
            wrap="none",
            font=("Consolas", 9),
            state="disabled",
            bg=CLR_BG,
            fg=CLR_FG_DIM,
            insertbackground=CLR_FG,
            selectbackground=CLR_SELECT_BG,
            selectforeground=CLR_FG,
            relief="flat",
            bd=2,
            padx=8,
            pady=4,
            undo=False,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")

        log_vsb = tk.Scrollbar(
            log_text_frame,
            orient="vertical",
            command=self.log_text.yview,
            bg=CLR_SURFACE,
            troughcolor=CLR_BG,
            activebackground=CLR_BORDER,
            relief="flat",
            bd=0,
            highlightthickness=0,
        )
        log_vsb.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=log_vsb.set)

        # log colour tags
        self.log_text.tag_configure("log_info", foreground=CLR_FG_DIM)
        self.log_text.tag_configure("log_warn", foreground=CLR_WARNING)
        self.log_text.tag_configure("log_error", foreground=CLR_ERROR)
        self.log_text.tag_configure("log_success", foreground=CLR_SUCCESS)

    def _build_action_bar(self, parent: tk.Frame) -> None:
        bar = tk.Frame(parent, bg=CLR_BG)
        bar.grid(row=5, column=0, sticky="ew")

        self.analyze_btn = tk.Button(
            bar,
            text="Analyze",
            command=self._on_analyze,
            bg=CLR_ACCENT,
            fg="white",
            activebackground="#1A6BB5",
            activeforeground="white",
            relief="flat",
            bd=5,
            font=("Segoe UI", 9, "bold"),
            cursor="hand2",
            width=10,
        )
        self.analyze_btn.pack(side="left", padx=(0, 6))

        self.cancel_btn = tk.Button(
            bar,
            text="Cancel",
            command=self._on_cancel,
            bg=CLR_SURFACE,
            fg=CLR_FG,
            activebackground=CLR_BORDER,
            activeforeground=CLR_FG,
            relief="flat",
            bd=5,
            font=("Segoe UI", 9),
            cursor="hand2",
            width=7,
        )

        # Dev log toggle — subtle, developer-oriented
        self.log_toggle_btn = tk.Button(
            bar,
            text="Dev Log",
            command=self._toggle_dev_log,
            bg=CLR_BG,
            fg=CLR_FG_DIM,
            activebackground=CLR_BORDER,
            activeforeground=CLR_FG,
            relief="flat",
            bd=4,
            font=("Segoe UI", 8),
            cursor="hand2",
            width=7,
        )
        self.log_toggle_btn.pack(side="left", padx=(2, 0))

        self.save_btn = tk.Button(
            bar,
            text="Save INI...",
            command=self._save_output,
            bg=CLR_SURFACE,
            fg=CLR_FG,
            activebackground=CLR_BORDER,
            activeforeground=CLR_FG,
            relief="flat",
            bd=5,
            font=("Segoe UI", 9),
            cursor="hand2",
            width=10,
            state="disabled",
        )
        self.save_btn.pack(side="right")

    # ── status ──────────────────────────────────────────────────────────

    def _set_status(self, text: str, colour: str = CLR_FG_DIM) -> None:
        self.status_label.configure(text=text, fg=colour)

    # ── dev log ─────────────────────────────────────────────────────────

    def _toggle_dev_log(self) -> None:
        """Show or hide the developer log panel."""
        if self._log_visible:
            self.log_frame.grid_remove()
            self.log_toggle_btn.configure(bg=CLR_BG, fg=CLR_FG_DIM)
            # shrink window back
            cur_h = self.root.winfo_height()
            self.root.geometry(f"{self.root.winfo_width()}x{max(cur_h - 150, 380)}")
        else:
            self.log_frame.grid(row=4, column=0, sticky="nsew", pady=(0, 4))
            self.log_toggle_btn.configure(bg=CLR_BORDER, fg=CLR_FG)
            self.log_text.see("end")
            # expand window to fit log panel
            cur_w = self.root.winfo_width()
            cur_h = self.root.winfo_height()
            self.root.geometry(f"{cur_w}x{cur_h + 150}")
        self._log_visible = not self._log_visible

    def _append_log(self, msg: str) -> None:
        """Append a line to the dev log with colour coding."""
        tag = "log_info"
        upper = msg.upper()
        if "ERROR" in upper or "FAIL" in upper:
            tag = "log_error"
        elif "WARN" in upper:
            tag = "log_warn"
        elif "found" in msg.lower() and "NOT" not in upper:
            tag = "log_success"
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.configure(state="disabled")
        if self._log_visible:
            self.log_text.see("end")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    # ── empty / result states ───────────────────────────────────────────

    def _show_empty_state(self) -> None:
        self._clear_output()
        self._set_status("Ready \u2014 Select a DLL and click Analyze")

    def _show_result(self, text: str) -> None:
        """Display the pure analysis result — no decoration in the output area."""
        self._clear_output()
        # Write the raw result directly into the Text widget, tagging offsets
        for line in text.splitlines():
            self._append_offset_line(line + "\n")
        self._analysis_done = True
        self.save_btn.configure(state="normal")
        # status line summary
        offset_count = text.count("Offset")
        self._set_status(
            f"Analysis complete \u2014 found {offset_count} offset(s)",
            CLR_SUCCESS,
        )

    def _show_error_state(self, error_msg: str) -> None:
        """Error with guided next steps in the output area (user might want to copy)."""
        self._clear_output()
        self._append_output("Analysis failed\n", "error")
        self._append_output("\u2500" * 48 + "\n", "dim")
        self._append_output(error_msg + "\n\n", "dim")

        current_mode = self.mode_var.get()
        if "pdb" in error_msg.lower() and current_mode == "symbol":
            self._append_output("Tip: switch to No-symbol mode (offline pattern scan)\n", "guide")
        else:
            self._append_output(
                "Check the DLL path and try again, or select a different file.\n",
                "guide",
            )
        self._analysis_done = True
        self._set_status("Analysis failed", CLR_ERROR)

    # ── output helpers ──────────────────────────────────────────────────

    def _clear_output(self, *, keep_state: bool = False) -> None:
        if not keep_state:
            self._analysis_done = False
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")

    def _append_output(self, text: str, tag: str = "") -> None:
        self.output_text.configure(state="normal")
        self.output_text.insert("end", text, tag)
        self.output_text.configure(state="disabled")
        self.output_text.see("end")

    def _append_offset_line(self, line: str) -> None:
        """Insert a line, tagging 0x… patterns as clickable."""
        self.output_text.configure(state="normal")
        pos = 0
        for m in re.finditer(r"0x[0-9A-Fa-f]{2,}", line):
            start, end = m.span()
            if start > pos:
                self.output_text.insert("end", line[pos:start])
            self.output_text.insert("end", line[start:end], "clickable")
            pos = end
        if pos < len(line):
            self.output_text.insert("end", line[pos:])
        self.output_text.configure(state="disabled")
        self.output_text.see("end")

    # ── analysis flow ───────────────────────────────────────────────────

    def _on_analyze(self) -> None:
        dll_path = Path(self.path_var.get())
        if not dll_path.exists():
            messagebox.showerror("File not found", f"DLL not found:\n{dll_path}")
            return

        use_symbols = self.mode_var.get() == "symbol"
        self._set_running(True)
        self._clear_output()
        self._clear_log()  # fresh log for each analysis run

        self._set_status("Loading...", CLR_ACCENT)

        self._cancel_event = threading.Event()

        def run_analysis() -> None:
            try:
                if self._cancel_event and self._cancel_event.is_set():
                    return

                def _on_progress(msg: str) -> None:
                    """Callback from the analysis pipeline — thread-safe."""
                    self._queue.put(("log", msg))

                self._queue.put(("status", "Analyzing... (PDB download may take a while)"))
                result = analyze_termsrv(
                    str(dll_path), use_symbols=use_symbols,
                    progress_callback=_on_progress,
                )
                if self._cancel_event and self._cancel_event.is_set():
                    self._queue.put(("cancelled", ""))
                    return
                self._queue.put(("result", result))
            except Exception as exc:  # noqa: BLE001
                self._queue.put(("error", str(exc)))

        thread = threading.Thread(target=run_analysis, daemon=True)
        thread.start()
        self._poll_queue()

    def _poll_queue(self) -> None:
        """Drain ALL pending messages each cycle — no truncation."""
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "status":
                    self._set_status(payload, CLR_ACCENT)
                elif kind == "log":
                    self._append_log(payload)
                elif kind == "cancelled":
                    self._set_status("Cancelled by user", CLR_WARNING)
                    self._append_log("--- Analysis cancelled by user ---")
                    self._set_running(False)
                    return  # terminal — stop polling
                elif kind == "result":
                    self._set_running(False)
                    self._append_log("--- Analysis complete ---")
                    self._show_result(payload)
                    return  # terminal — stop polling
                elif kind == "error":
                    self._set_running(False)
                    self._append_log(f"ERROR: {payload}")
                    self._show_error_state(payload)
                    return  # terminal — stop polling
                # non-terminal: keep draining the queue
        except queue.Empty:
            self._after_id = self.root.after(80, self._poll_queue)

    def _on_cancel(self) -> None:
        if self._cancel_event is None:
            return
        self._cancel_event.set()
        self.cancel_btn.configure(text="Cancelling...", state="disabled", bg=CLR_WIDGET_BG)
        self._set_status("Cancelling...", CLR_WARNING)

    # ── ui state ────────────────────────────────────────────────────────

    def _set_running(self, running: bool) -> None:
        if running:
            self.analyze_btn.configure(text="Analyzing...", state="disabled")
            self.save_btn.configure(state="disabled")
            self.cancel_btn.pack(side="left", padx=(0, 6), before=self.save_btn)
        else:
            self.analyze_btn.configure(text="Analyze", state="normal")
            self.cancel_btn.pack_forget()
            self._cancel_event = None

    def _validate_path_silent(self) -> None:
        path = Path(self.path_var.get())
        if path.is_file():
            self.path_entry.configure(fg=CLR_FG)
        else:
            self.path_entry.configure(fg=CLR_WARNING)

    # ── file operations ─────────────────────────────────────────────────

    def _browse_file(self) -> None:
        initial = Path(self.path_var.get())
        if not initial.exists():
            initial = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32"
        path = filedialog.askopenfilename(
            title="Select termsrv.dll",
            initialdir=str(initial.parent) if initial.is_file() else str(initial),
            initialfile=initial.name if initial.is_file() else "termsrv.dll",
            filetypes=[("DLL files", "*.dll"), ("All files", "*.*")],
        )
        if path:
            self.path_var.set(path)
            self._validate_path_silent()

    def _copy_to_clipboard(self, text: str, label: str = "") -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        if label:
            self._set_status(f"Copied {label} to clipboard", CLR_SUCCESS)
            self.root.after(1800, lambda: None)

    def _on_click_offset(self, event: tk.Event) -> None:
        """Click any 0x… offset to copy it instantly."""
        try:
            idx = self.output_text.index(f"@{event.x},{event.y}")
            for tag in self.output_text.tag_names(idx):
                if tag == "clickable":
                    word = self.output_text.get(f"{idx} wordstart", f"{idx} wordend")
                    self._copy_to_clipboard(word.strip(), word.strip())
                    self.output_text.tag_add("sel", f"{idx} wordstart", f"{idx} wordend")
                    self.root.after(300, lambda: self.output_text.tag_remove("sel", "1.0", "end"))
                    return
        except tk.TclError:
            pass

    def _save_output(self) -> None:
        text = self.output_text.get("1.0", "end-1c")
        if not text.strip():
            messagebox.showwarning("Nothing to save", "Run an analysis first.")
            return

        default = Path(self.path_var.get())
        filename = f"{default.stem}.ini" if default.name else "rdpwrap.ini"
        path = filedialog.asksaveasfilename(
            title="Save INI configuration",
            defaultextension=".ini",
            initialfile=filename,
            filetypes=[("INI files", "*.ini"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            Path(path).write_text(text, encoding="utf-8")
            self._set_status(f"Saved to {Path(path).name}", CLR_SUCCESS)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Save failed", f"Could not save file:\n{exc}")

    # ── misc ────────────────────────────────────────────────────────────

    def _select_all(self) -> str:
        self.output_text.tag_add("sel", "1.0", "end")
        self.output_text.mark_set("insert", "1.0")
        self.output_text.see("insert")
        return "break"

    def _on_close(self) -> None:
        if self._cancel_event is not None:
            self._cancel_event.set()
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
        self.root.destroy()


def main() -> None:
    root = tk.Tk()

    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(".", background=CLR_BG, foreground=CLR_FG)
    style.configure("TFrame", background=CLR_BG)
    style.configure("TLabel", background=CLR_BG, foreground=CLR_FG)
    style.configure("TButton",
        background=CLR_SURFACE,
        foreground=CLR_FG,
        borderwidth=0,
        padding=6,
        font=("Segoe UI", 9),
    )
    style.map("TButton",
        background=[("active", CLR_BORDER), ("disabled", CLR_BG)],
        foreground=[("disabled", CLR_FG_DISABLED)],
    )
    style.configure("TRadiobutton",
        background=CLR_BG,
        foreground=CLR_FG,
        font=("Segoe UI", 9),
    )
    style.map("TRadiobutton",
        background=[("active", CLR_BG)],
        foreground=[("selected", CLR_FG)],
    )
    style.configure("TEntry",
        fieldbackground=CLR_WIDGET_BG,
        foreground=CLR_FG,
        borderwidth=0,
        padding=5,
    )
    style.configure("TSeparator", background=CLR_BORDER)
    style.configure("TScrollbar",
        background=CLR_SURFACE,
        troughcolor=CLR_BG,
        borderwidth=0,
        arrowsize=14,
    )

    app = RdpWrapGui(root)
    root.mainloop()


if __name__ == "__main__":
    main()
