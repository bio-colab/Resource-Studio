"""Legacy Tkinter fallback; the supported Windows desktop UI is the WPF shell.

This module remains useful on environments without WPF, but it intentionally does
not expose the complete Verification, forensic, or typed-editor surface.
"""

from __future__ import annotations

import json
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from core.compatibility import inspect_compatibility
from core.health import PEHealth
from core.hex_view import HexViewer
from core.pe_inspector import PEInspector
from core.pe_metadata import PEMetadataInspector
from core.project import Project, ResourceEntry
from core.signature import inspect_signature
from core.search import search_resources


class ResourceStudioApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Resource Studio")
        self.geometry("1180x720")
        self.minsize(900, 560)
        self.project: Project | None = None
        self.source_path: Path | None = None
        self._workspace = tempfile.TemporaryDirectory(prefix="resource-studio-gui-")
        self._entries: dict[str, ResourceEntry] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        toolbar = ttk.Frame(self, padding=8)
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open PE", command=self.open_pe).pack(side="left")
        ttk.Button(toolbar, text="Validate", command=self.validate).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Inspect", command=self.inspect).pack(side="left", padx=(6, 0))
        ttk.Button(toolbar, text="Save As / Build", command=self.build_as).pack(side="left", padx=(6, 0))
        ttk.Label(toolbar, text="Search:").pack(side="left", padx=(22, 4))
        self.search_var = tk.StringVar()
        search = ttk.Entry(toolbar, textvariable=self.search_var, width=28)
        search.pack(side="left")
        search.bind("<Return>", lambda _event: self.search())
        ttk.Button(toolbar, text="Find", command=self.search).pack(side="left", padx=(6, 0))
        self.path_var = tk.StringVar(value="No PE opened")
        ttk.Label(toolbar, textvariable=self.path_var).pack(side="right")

        splitter = ttk.PanedWindow(self, orient="horizontal")
        splitter.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        left = ttk.Frame(splitter, padding=4)
        right = ttk.Frame(splitter, padding=4)
        splitter.add(left, weight=3)
        splitter.add(right, weight=2)

        columns = ("type", "name", "language", "size", "sha256")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        headings = {"type": "Type", "name": "Name", "language": "Language", "size": "Size", "sha256": "SHA-256"}
        widths = {"type": 120, "name": 170, "language": 80, "size": 80, "sha256": 280}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self.show_selected())
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        ttk.Label(right, text="Details", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.details = tk.Text(right, wrap="word", state="disabled", height=20)
        self.details.pack(fill="both", expand=True, pady=(4, 8))
        ttk.Label(right, text="Hex preview", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.hex_text = tk.Text(right, height=12, wrap="none", state="disabled", font=("Consolas", 9))
        self.hex_text.pack(fill="both", expand=True, pady=(4, 0))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=4).pack(fill="x")

    def open_pe(self) -> None:
        filename = filedialog.askopenfilename(title="Open PE", filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if not filename:
            return
        try:
            self.source_path = Path(filename).resolve()
            self.project = Project.open_pe(self.source_path, Path(self._workspace.name) / "project")
            self._entries = {str(index): entry for index, entry in enumerate(self.project.entries.values())}
            self._refresh_tree()
            self.path_var.set(str(self.source_path))
            self.status_var.set(f"Opened {len(self._entries)} resources")
            self.show_json({"compatibility": inspect_compatibility(self.source_path).to_dict(), "signature": inspect_signature(self.source_path).to_dict()})
        except Exception as exc:
            self._error("Open failed", exc)

    def _refresh_tree(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for key, entry in self._entries.items():
            self.tree.insert("", "end", iid=key, values=(entry.resource_type, entry.name, entry.language or "", len(entry.data), entry.sha256))

    def selected_entry(self) -> ResourceEntry | None:
        selection = self.tree.selection()
        return self._entries.get(selection[0]) if selection else None

    def show_selected(self) -> None:
        entry = self.selected_entry()
        if entry is None:
            return
        metadata = {"type": entry.resource_type, "name": entry.name, "language": entry.language, "size": len(entry.data), "sha256": entry.sha256, "metadata": entry.metadata}
        self.show_json(metadata, self.details)
        preview = HexViewer(entry.data).slice(0, min(256, len(entry.data)))
        self.set_text(self.hex_text, f"offset={preview.offset}\\n{preview.hex()}\\n\\n{preview.ascii()}")

    def search(self) -> None:
        query = self.search_var.get().strip()
        if not query or self.project is None:
            return
        try:
            hits = search_resources(self._entries.values(), query)
            self.show_json([hit.to_dict() for hit in hits])
            self.status_var.set(f"{len(hits)} search hits")
        except Exception as exc:
            self._error("Search failed", exc)

    def validate(self) -> None:
        if self.source_path is None:
            return
        try:
            self.show_json(PEHealth.inspect(self.source_path).to_dict())
            self.status_var.set("Validation complete")
        except Exception as exc:
            self._error("Validation failed", exc)

    def inspect(self) -> None:
        if self.source_path is None:
            return
        try:
            self.show_json({"pe": PEInspector.inspect(self.source_path).to_dict(), "metadata": PEMetadataInspector.inspect(self.source_path).to_dict(), "signature": inspect_signature(self.source_path).to_dict(), "compatibility": inspect_compatibility(self.source_path).to_dict()})
            self.status_var.set("Inspection complete")
        except Exception as exc:
            self._error("Inspect failed", exc)

    def build_as(self) -> None:
        if self.project is None:
            return
        filename = filedialog.asksaveasfilename(title="Save PE As", defaultextension=self.source_path.suffix if self.source_path else ".dll", filetypes=[("PE files", "*.exe *.dll *.sys"), ("All files", "*.*")])
        if not filename:
            return
        try:
            output = self.project.build(Path(filename).resolve())
            self.status_var.set(f"Built {output}")
            messagebox.showinfo("Build complete", f"Saved to:\n{output}")
        except Exception as exc:
            self._error("Build failed", exc)

    def show_json(self, payload: object, widget: tk.Text | None = None) -> None:
        self.set_text(widget or self.details, json.dumps(payload, ensure_ascii=False, indent=2, default=str))

    @staticmethod
    def set_text(widget: tk.Text, content: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    @staticmethod
    def _error(title: str, exc: Exception) -> None:
        messagebox.showerror(title, str(exc))


if __name__ == "__main__":
    ResourceStudioApp().mainloop()
