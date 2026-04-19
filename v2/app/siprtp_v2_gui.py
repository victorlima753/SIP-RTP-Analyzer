#!/usr/bin/env python3
"""Tkinter GUI for SIP/RTP Analyzer V2."""

from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
APP_DIR = Path(__file__).resolve().parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from siprtp_v2_tk_runtime import configure_tcl_runtime  # noqa: E402

configure_tcl_runtime()

import tkinter as tk  # noqa: E402
from tkinter import filedialog, messagebox, ttk  # noqa: E402

try:  # pragma: no cover
    from . import siprtp_v2_core
    from . import siprtp_v2_export
except ImportError:  # pragma: no cover
    import siprtp_v2_core
    import siprtp_v2_export


APP_TITLE = "SIP/RTP Analyzer V2"


class SipRtpV2Gui(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1180x760")
        self.minsize(920, 620)
        self.configure(bg="#f5f7fa")

        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.results_by_iid: dict[str, dict[str, object]] = {}
        self.last_output_dir: Path | None = None

        self.sip_dir_var = tk.StringVar()
        self.rtp_dir_var = tk.StringVar()
        self.db_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.sip_servers_var = tk.StringVar(value="177.53.16.6,177.53.16.41")
        self.rtp_servers_var = tk.StringVar(value="177.53.16.42,177.53.16.43,177.53.16.45")
        self.time_var = tk.StringVar()
        self.window_var = tk.StringVar(value="10")
        self.margin_var = tk.StringVar(value="10")
        self.status_var = tk.StringVar(value="Pronto.")
        self.use_rust_var = tk.BooleanVar(value=True)
        self.filter_rtp_by_sdp_var = tk.BooleanVar(value=True)
        self.performance_profile_var = tk.StringVar(value="Equilibrado")
        self.workers_var = tk.StringVar(value="Auto")

        self._build_style()
        self._build_layout()
        self.after(100, self._drain_events)

    def _build_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Root.TFrame", background="#f5f7fa")
        style.configure("Card.TFrame", background="#ffffff")
        style.configure("TLabel", background="#f5f7fa", foreground="#1f2933", font=("Segoe UI", 10))
        style.configure("Card.TLabel", background="#ffffff", foreground="#1f2933", font=("Segoe UI", 10))
        style.configure("Section.TLabel", background="#ffffff", foreground="#102a43", font=("Segoe UI", 11, "bold"))
        style.configure("Hint.TLabel", background="#f5f7fa", foreground="#52606d", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#f5f7fa", foreground="#102a43", font=("Segoe UI", 22, "bold"))
        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"), padding=(14, 8))
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
        style.configure("Card.TCheckbutton", background="#ffffff", foreground="#1f2933", font=("Segoe UI", 9))
        style.configure("Treeview", font=("Segoe UI", 9), rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _build_layout(self) -> None:
        shell = ttk.Frame(self, style="Root.TFrame")
        shell.pack(fill="both", expand=True)
        shell.columnconfigure(0, weight=1)
        shell.rowconfigure(0, weight=1)

        self._scroll_canvas = tk.Canvas(shell, bg="#f5f7fa", bd=0, highlightthickness=0)
        self._scroll_canvas.grid(row=0, column=0, sticky="nsew")
        page_scroll = ttk.Scrollbar(shell, orient="vertical", command=self._scroll_canvas.yview)
        page_scroll.grid(row=0, column=1, sticky="ns")
        self._scroll_canvas.configure(yscrollcommand=page_scroll.set)

        root = ttk.Frame(self._scroll_canvas, style="Root.TFrame", padding=(18, 18, 18, 18))
        self._scroll_window = self._scroll_canvas.create_window((0, 0), window=root, anchor="nw")
        root.bind("<Configure>", self._update_scroll_region)
        self._scroll_canvas.bind("<Configure>", self._resize_scroll_window)
        self._scroll_canvas.bind("<Enter>", self._enable_page_wheel)
        self._scroll_canvas.bind("<Leave>", self._disable_page_wheel)
        root.columnconfigure(0, weight=1)

        header = ttk.Frame(root, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(header, text=APP_TITLE, style="Title.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="Indexe pastas SIP/RTP separadas, busque por numero e horario, exporte apenas a chamada.",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(2, 0))

        paths = self._card(root)
        paths.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        paths.columnconfigure(1, weight=1)
        self._section(paths, "Pastas", columnspan=3)
        self._path_row(paths, 1, "Pasta SIP", self.sip_dir_var, self._browse_sip)
        self._path_row(paths, 2, "Pasta RTP", self.rtp_dir_var, self._browse_rtp)
        self._path_row(paths, 3, "Database", self.db_var, self._browse_db)
        self._path_row(paths, 4, "Saida", self.out_var, self._browse_output)

        servers = self._card(root)
        servers.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        servers.columnconfigure(1, weight=1)
        servers.columnconfigure(3, weight=1)
        self._section(servers, "Ambiente", columnspan=4)
        ttk.Label(servers, text="Servidores SIP", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4, padx=(0, 10))
        ttk.Entry(servers, textvariable=self.sip_servers_var).grid(row=1, column=1, columnspan=3, sticky="ew", pady=4)
        ttk.Label(servers, text="Servidores RTP", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4, padx=(0, 10))
        ttk.Entry(servers, textvariable=self.rtp_servers_var).grid(row=2, column=1, columnspan=3, sticky="ew", pady=4)
        ttk.Label(servers, text="Desempenho", style="Card.TLabel").grid(row=3, column=0, sticky="w", pady=(8, 0), padx=(0, 10))
        ttk.Combobox(
            servers,
            width=13,
            textvariable=self.performance_profile_var,
            values=("Seguro", "Equilibrado", "Turbo"),
            state="readonly",
        ).grid(row=3, column=1, sticky="w", pady=(8, 0), padx=(0, 14))
        ttk.Label(servers, text="Workers", style="Card.TLabel").grid(row=3, column=2, sticky="w", pady=(8, 0), padx=(0, 10))
        ttk.Entry(servers, width=10, textvariable=self.workers_var).grid(row=3, column=3, sticky="w", pady=(8, 0))
        ttk.Label(
            servers,
            text="Usado na indexacao Rust e na exportacao. Use Auto ou informe um numero fixo de threads.",
            style="Card.TLabel",
        ).grid(row=4, column=0, columnspan=4, sticky="w", pady=(6, 0))
        ttk.Checkbutton(
            servers,
            text="Usar motor Rust quando disponivel",
            variable=self.use_rust_var,
            style="Card.TCheckbutton",
        ).grid(row=5, column=0, columnspan=4, sticky="w", pady=(8, 0))

        index_card = self._card(root)
        index_card.grid(row=3, column=0, sticky="ew", pady=(0, 12))
        index_card.columnconfigure(0, weight=1)
        self._section(index_card, "Indexacao")
        self.index_button = ttk.Button(index_card, text="Indexar pastas", command=self._start_index, style="Primary.TButton")
        self.index_button.grid(row=1, column=0, sticky="ew")
        ttk.Label(index_card, textvariable=self.status_var, style="Card.TLabel").grid(row=2, column=0, sticky="ew", pady=(8, 0))
        self.progress = ttk.Progressbar(index_card, mode="indeterminate")
        self.progress.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self.index_log = self._text_box(index_card, row=4, height=5)

        search = self._card(root)
        search.grid(row=4, column=0, sticky="ew", pady=(0, 12))
        search.columnconfigure(0, weight=1)
        self._section(search, "Busca de chamadas")

        query = ttk.Frame(search, style="Card.TFrame")
        query.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        query.columnconfigure(0, weight=3)
        query.columnconfigure(1, weight=1)

        numbers_panel = ttk.Frame(query, style="Card.TFrame")
        numbers_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        numbers_panel.columnconfigure(0, weight=1)
        ttk.Label(numbers_panel, text="Numero(s)", style="Card.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            numbers_panel,
            text="Use uma linha por chamada. Opcional: numero; 2026-04-17 15:57:36",
            style="Card.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(2, 4))
        self.numbers_text = tk.Text(numbers_panel, height=4, width=32, wrap="none", bd=1, relief="solid", font=("Segoe UI", 10))
        self.numbers_text.grid(row=2, column=0, sticky="ew")

        filters_panel = ttk.Frame(query, style="Card.TFrame")
        filters_panel.grid(row=0, column=1, sticky="new")
        filters_panel.columnconfigure(1, weight=1)
        ttk.Label(filters_panel, text="Horario padrao", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 6), padx=(0, 8))
        ttk.Entry(filters_panel, textvariable=self.time_var).grid(row=0, column=1, sticky="ew", pady=(0, 6))
        ttk.Label(filters_panel, text="Janela min.", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(filters_panel, width=8, textvariable=self.window_var).grid(row=1, column=1, sticky="w")
        self.search_button = ttk.Button(search, text="Buscar", command=self._start_search, style="Primary.TButton")
        self.search_button.grid(row=2, column=0, sticky="ew", pady=(12, 0))

        columns = ("numero", "horario", "inicio", "fim", "duracao", "status", "origem", "destino", "call_id")
        table = ttk.Frame(search, style="Card.TFrame")
        table.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        table.configure(height=300)
        table.grid_propagate(False)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.results = ttk.Treeview(table, columns=columns, show="headings", selectmode="extended", height=9)
        for column, title, width in [
            ("numero", "Numero", 130),
            ("horario", "Horario busca", 150),
            ("inicio", "Inicio", 145),
            ("fim", "Fim", 145),
            ("duracao", "Dur(s)", 70),
            ("status", "SIP", 60),
            ("origem", "Origem", 120),
            ("destino", "Destino", 170),
            ("call_id", "Call-ID", 280),
        ]:
            self.results.heading(column, text=title)
            self.results.column(column, width=width, anchor="w", stretch=True)
        results_y = ttk.Scrollbar(table, orient="vertical", command=self.results.yview)
        results_x = ttk.Scrollbar(table, orient="horizontal", command=self.results.xview)
        self.results.configure(yscrollcommand=results_y.set, xscrollcommand=results_x.set)
        self.results.grid(row=0, column=0, sticky="nsew")
        results_y.grid(row=0, column=1, sticky="ns")
        results_x.grid(row=1, column=0, sticky="ew")

        actions = self._card(root)
        actions.grid(row=5, column=0, sticky="ew", pady=(0, 12))
        actions.columnconfigure(6, weight=1)
        self._section(actions, "Exportacao", columnspan=7)
        ttk.Label(actions, text="Margem seg.", style="Card.TLabel").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        ttk.Entry(actions, width=8, textvariable=self.margin_var).grid(row=1, column=1, sticky="w", padx=(0, 12), pady=(8, 0))
        ttk.Checkbutton(
            actions,
            text="Filtrar RTP por SDP",
            variable=self.filter_rtp_by_sdp_var,
            style="Card.TCheckbutton",
        ).grid(row=1, column=2, sticky="w", padx=(0, 12), pady=(8, 0))
        self.export_selected_button = ttk.Button(actions, text="Exportar selecionadas", command=self._start_export_selected, style="Primary.TButton")
        self.export_selected_button.grid(row=2, column=0, columnspan=3, sticky="ew", padx=(0, 10), pady=(12, 0))
        self.export_all_button = ttk.Button(actions, text="Exportar todas encontradas", command=self._start_export_all)
        self.export_all_button.grid(row=2, column=3, columnspan=3, sticky="ew", padx=(0, 10), pady=(12, 0))
        ttk.Button(actions, text="Abrir pasta", command=self._open_output_dir).grid(row=2, column=6, sticky="w", pady=(12, 0))

        log_card = self._card(root)
        log_card.grid(row=6, column=0, sticky="ew")
        log_card.columnconfigure(0, weight=1)
        self._section(log_card, "Datalog V2")
        self.log = self._text_box(log_card, row=1, height=6)

    def _card(self, parent: ttk.Frame) -> ttk.Frame:
        return ttk.Frame(parent, style="Card.TFrame", padding=14)

    def _section(self, parent: ttk.Frame, title: str, columnspan: int = 1) -> None:
        ttk.Label(parent, text=title, style="Section.TLabel").grid(
            row=0,
            column=0,
            columnspan=columnspan,
            sticky="w",
            pady=(0, 8),
        )

    def _path_row(self, parent: ttk.Frame, row: int, label: str, variable: tk.StringVar, command) -> None:
        ttk.Label(parent, text=label, style="Card.TLabel").grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
        ttk.Entry(parent, textvariable=variable).grid(row=row, column=1, sticky="ew", pady=4, padx=(0, 10))
        ttk.Button(parent, text="Selecionar", command=command).grid(row=row, column=2, sticky="ew", pady=4)

    def _text_box(self, parent: ttk.Frame, row: int, height: int) -> tk.Text:
        holder = ttk.Frame(parent, style="Card.TFrame")
        holder.grid(row=row, column=0, sticky="ew", pady=(8, 0))
        holder.columnconfigure(0, weight=1)
        text = tk.Text(holder, height=height, wrap="word", bd=1, relief="solid", font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(holder, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        text.grid(row=0, column=0, sticky="ew")
        scrollbar.grid(row=0, column=1, sticky="ns")
        return text

    def _update_scroll_region(self, _event: tk.Event) -> None:
        self._scroll_canvas.configure(scrollregion=self._scroll_canvas.bbox("all"))

    def _resize_scroll_window(self, event: tk.Event) -> None:
        self._scroll_canvas.itemconfigure(self._scroll_window, width=event.width)

    def _enable_page_wheel(self, _event: tk.Event) -> None:
        self.bind_all("<MouseWheel>", self._on_page_wheel)

    def _disable_page_wheel(self, _event: tk.Event) -> None:
        self.unbind_all("<MouseWheel>")

    def _on_page_wheel(self, event: tk.Event) -> None:
        if isinstance(event.widget, (tk.Text, ttk.Treeview)):
            return
        self._scroll_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _browse_sip(self) -> None:
        value = filedialog.askdirectory(title="Selecionar pasta SIP")
        if value:
            self.sip_dir_var.set(value)
            self._suggest_db()

    def _browse_rtp(self) -> None:
        value = filedialog.askdirectory(title="Selecionar pasta RTP")
        if value:
            self.rtp_dir_var.set(value)
            self._suggest_db()

    def _browse_db(self) -> None:
        value = filedialog.asksaveasfilename(title="Selecionar database", defaultextension=".sqlite", filetypes=[("SQLite", "*.sqlite *.db"), ("Todos", "*.*")])
        if value:
            self.db_var.set(value)

    def _browse_output(self) -> None:
        value = filedialog.askdirectory(title="Selecionar pasta de saida")
        if value:
            self.out_var.set(value)

    def _suggest_db(self) -> None:
        if self.db_var.get().strip():
            return
        sip = Path(self.sip_dir_var.get()) if self.sip_dir_var.get().strip() else None
        rtp = Path(self.rtp_dir_var.get()) if self.rtp_dir_var.get().strip() else None
        if sip:
            self.db_var.set(str(siprtp_v2_core.default_db_path_for_dirs(sip, rtp)))
            self.out_var.set(str((sip.parent if sip.name.lower() == "sip" else sip) / "v2_exports"))

    def _start_index(self) -> None:
        sip_dir = self._require_dir(self.sip_dir_var.get(), "Selecione a pasta SIP.")
        rtp_dir = self._require_dir(self.rtp_dir_var.get(), "Selecione a pasta RTP.")
        if not sip_dir or not rtp_dir:
            return
        db_path = Path(self.db_var.get()) if self.db_var.get().strip() else siprtp_v2_core.default_db_path_for_dirs(sip_dir, rtp_dir)
        self.db_var.set(str(db_path))
        self.index_log.delete("1.0", "end")

        def work() -> dict[str, object]:
            return siprtp_v2_core.index_folders(
                sip_dir=sip_dir,
                rtp_dir=rtp_dir,
                db_path=db_path,
                sip_servers=self.sip_servers_var.get(),
                rtp_servers=self.rtp_servers_var.get(),
                force=True,
                prefer_rust=self.use_rust_var.get(),
                performance_profile=self._performance_profile_key(),
                workers=self.workers_var.get(),
                progress_callback=self._thread_index_event,
            )

        self._run_task("Indexando pastas V2...", work, self._finish_index)

    def _start_search(self) -> None:
        db_path = self._require_file(self.db_var.get(), "Selecione ou crie o database V2 primeiro.")
        if not db_path:
            return
        queries = self._parse_queries()
        if not queries:
            messagebox.showwarning(APP_TITLE, "Informe pelo menos um numero e horario.")
            return
        try:
            window = float(self.window_var.get().replace(",", "."))
        except ValueError:
            messagebox.showwarning(APP_TITLE, "Janela deve ser numero em minutos.")
            return

        def work() -> list[dict[str, object]]:
            rows: list[dict[str, object]] = []
            for number, call_time in queries:
                self._thread_log(f"Buscando {number} em {call_time}...")
                found = siprtp_v2_core.find_calls(db_path, number, call_time, window)
                for row in found:
                    row["_query_number"] = number
                    row["_query_time"] = call_time
                    rows.append(row)
            return rows

        self._run_task("Buscando chamadas V2...", work, self._finish_search)

    def _start_export_selected(self) -> None:
        selection = self.results.selection()
        if not selection:
            messagebox.showwarning(APP_TITLE, "Selecione uma ou mais chamadas.")
            return
        self._start_export([self.results_by_iid[iid] for iid in selection if iid in self.results_by_iid])

    def _start_export_all(self) -> None:
        rows = list(self.results_by_iid.values())
        if not rows:
            messagebox.showwarning(APP_TITLE, "Busque chamadas antes de exportar.")
            return
        self._start_export(rows)

    def _start_export(self, rows: list[dict[str, object]]) -> None:
        db_path = self._require_file(self.db_var.get(), "Selecione ou crie o database V2 primeiro.")
        if not db_path:
            return
        out_dir = Path(self.out_var.get()) if self.out_var.get().strip() else db_path.parent / "v2_exports"
        try:
            margin = float(self.margin_var.get().replace(",", "."))
        except ValueError:
            messagebox.showwarning(APP_TITLE, "Margem deve ser numero em segundos.")
            return

        def work() -> list[dict[str, object]]:
            exported: list[dict[str, object]] = []
            for index, row in enumerate(rows, start=1):
                self._thread_log(f"Exportando {index}/{len(rows)}: {row.get('call_id')}")
                result = siprtp_v2_export.export_call(
                    db_path=db_path,
                    call_id=str(row["call_id"]),
                    out_dir=out_dir,
                    margin_seconds=margin,
                    filter_rtp_by_sdp=self.filter_rtp_by_sdp_var.get(),
                    performance_profile=self._performance_profile_key(),
                    workers=self.workers_var.get(),
                    status_callback=self._thread_log,
                )
                exported.append(result)
            return exported

        self._run_task("Exportando chamadas V2...", work, self._finish_export)

    def _performance_profile_key(self) -> str:
        value = self.performance_profile_var.get().strip().lower()
        return {
            "seguro": "safe",
            "equilibrado": "balanced",
            "turbo": "turbo",
        }.get(value, "balanced")

    def _parse_queries(self) -> list[tuple[str, str]]:
        default_time = self.time_var.get().strip()
        raw = self.numbers_text.get("1.0", "end").strip()
        lines: list[str] = []
        for line in raw.splitlines():
            clean = line.strip()
            if not clean:
                continue
            if ";" not in clean and "\t" not in clean and "," in clean:
                lines.extend(part.strip() for part in clean.split(",") if part.strip())
            else:
                lines.append(clean)
        queries: list[tuple[str, str]] = []
        for line in lines:
            number = line
            call_time = default_time
            for separator in (";", "\t", ","):
                if separator in line:
                    first, second = line.split(separator, 1)
                    number = first.strip()
                    call_time = second.strip() or default_time
                    break
            if number and call_time:
                queries.append((number, call_time))
        return queries

    def _run_task(self, title: str, work, done) -> None:
        self._set_busy(True, title)
        self._append_log(title)

        def target() -> None:
            try:
                result = work()
            except Exception as exc:
                self.events.put(("error", f"{exc}\n\n{traceback.format_exc()}"))
            else:
                self.events.put(("done", (done, result)))

        threading.Thread(target=target, daemon=True).start()

    def _thread_log(self, message: str) -> None:
        self.events.put(("log", message))

    def _thread_index_event(self, payload: dict[str, object]) -> None:
        self.events.put(("index", payload))

    def _drain_events(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self._append_log(str(payload))
                elif kind == "index":
                    self._append_index_log(siprtp_v2_core.format_progress(payload))  # type: ignore[arg-type]
                elif kind == "error":
                    self._set_busy(False, "Erro.")
                    self._append_log(str(payload))
                    self._append_index_log(str(payload))
                    messagebox.showerror(APP_TITLE, str(payload).splitlines()[0])
                elif kind == "done":
                    done, result = payload  # type: ignore[misc]
                    done(result)
                    self._set_busy(False, "Pronto.")
        except queue.Empty:
            pass
        self.after(100, self._drain_events)

    def _finish_index(self, result: dict[str, object]) -> None:
        self._append_index_log(f"Indice pronto: {result}")
        self._append_log(f"Indice pronto: {result}")

    def _finish_search(self, rows: list[dict[str, object]]) -> None:
        for iid in self.results.get_children():
            self.results.delete(iid)
        self.results_by_iid.clear()
        for index, row in enumerate(rows, start=1):
            iid = str(index)
            self.results_by_iid[iid] = row
            self.results.insert(
                "",
                "end",
                iid=iid,
                values=(
                    row.get("_query_number", ""),
                    row.get("_query_time", ""),
                    row.get("inicio", ""),
                    row.get("fim", ""),
                    row.get("duracao_seg", ""),
                    row.get("status_code", ""),
                    row.get("from_user", ""),
                    row.get("to_user", ""),
                    row.get("call_id", ""),
                ),
            )
        if rows:
            self.results.selection_set("1")
            self.results.focus("1")
        self._append_log(f"Busca V2 concluida: {len(rows)} chamada(s).")

    def _finish_export(self, exported: list[dict[str, object]]) -> None:
        if exported:
            self.last_output_dir = Path(str(exported[-1]["pcap"])).parent
        for item in exported:
            self._append_log(f"PCAP reduzido: {item.get('pcap')}")
            self._append_log(f"Relatorio JSON: {item.get('report_json')}")
            self._append_log(f"Relatorio HTML: {item.get('report_html')}")
        messagebox.showinfo(APP_TITLE, f"{len(exported)} chamada(s) exportada(s).")

    def _require_dir(self, value: str, warning: str) -> Path | None:
        if not value.strip():
            messagebox.showwarning(APP_TITLE, warning)
            return None
        path = Path(value)
        if not path.is_dir():
            messagebox.showwarning(APP_TITLE, f"Pasta nao encontrada:\n{path}")
            return None
        return path

    def _require_file(self, value: str, warning: str) -> Path | None:
        if not value.strip():
            messagebox.showwarning(APP_TITLE, warning)
            return None
        path = Path(value)
        if not path.exists():
            messagebox.showwarning(APP_TITLE, f"Arquivo nao encontrado:\n{path}")
            return None
        return path

    def _open_output_dir(self) -> None:
        target = self.last_output_dir or Path(self.out_var.get() or ".")
        if not target.exists():
            messagebox.showwarning(APP_TITLE, f"Pasta nao encontrada:\n{target}")
            return
        os.startfile(target)

    def _set_busy(self, busy: bool, status: str) -> None:
        self.status_var.set(status)
        state = "disabled" if busy else "normal"
        for button in (self.index_button, self.search_button, self.export_selected_button, self.export_all_button):
            button.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _append_index_log(self, message: str) -> None:
        self.index_log.insert("end", message + "\n")
        self.index_log.see("end")

    def _append_log(self, message: str) -> None:
        self.log.insert("end", message + "\n")
        self.log.see("end")


def main() -> None:
    if "--smoke-test" in sys.argv:
        app = SipRtpV2Gui()
        app.withdraw()
        app.update_idletasks()
        app.destroy()
        return
    app = SipRtpV2Gui()
    app.mainloop()


if __name__ == "__main__":
    main()
