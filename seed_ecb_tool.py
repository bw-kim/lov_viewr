"""Local SEED-128 ECB tool. Run without arguments for the desktop window.

For a large file on a terminal:
    python seed_ecb_tool.py --cli encrypt input.bin output.seed
    python seed_ecb_tool.py --cli decrypt output.seed recovered.bin
The CLI prompts for the key rather than exposing it in process arguments.
"""

from __future__ import annotations

import argparse
import getpass
import io
import os
import queue
import sys
import tempfile
import threading
import time
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext, ttk
except ImportError:
    tk = None

try:
    from seed_ecb_core import decode_value, encode_value, parse_key, transform_stream
except ImportError as exc:
    if exc.name and exc.name.startswith("cryptography"):
        raise SystemExit("cryptography 패키지가 필요합니다: python -m pip install -r requirements-seed.txt") from exc
    raise

FORMAT_LABELS = {"utf8": "문자열 (UTF-8)", "hex": "Hex", "base64": "Base64"}
PADDING_LABELS = {"pkcs7": "PKCS#7 (기본)", "none": "없음 (16바이트 배수)", "zero": "0x00 채우기"}
PREVIEW_CHARS = 200_000


def selected_value(label: str, choices: dict[str, str]) -> str:
    for value, display in choices.items():
        if label == display:
            return value
    raise ValueError("선택한 형식을 확인하세요.")


def convert_file(
    source_path: Path,
    destination_path: Path,
    key: bytes,
    *,
    decrypt: bool,
    padding: str,
    progress=None,
) -> tuple[int, int]:
    """Write to a temporary file, then replace the destination on success."""
    if source_path.resolve() == destination_path.resolve():
        raise ValueError("원본 파일과 저장할 파일은 서로 달라야 합니다.")
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with source_path.open("rb") as source, tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{destination_path.name}.", suffix=".part", dir=destination_path.parent, delete=False
        ) as destination:
            temporary = Path(destination.name)
            counts = transform_stream(source, destination, key, decrypt=decrypt, padding=padding, progress=progress)
        os.replace(temporary, destination_path)
        temporary = None
        return counts
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class SeedWindow:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("SEED-ECB 암복호화 도구")
        self.root.geometry("1020x780")
        self.root.minsize(780, 650)
        self.mode = tk.StringVar(value="encrypt")
        self.key_format = tk.StringVar(value=FORMAT_LABELS["utf8"])
        self.key_text = tk.StringVar()
        self.padding = tk.StringVar(value=PADDING_LABELS["pkcs7"])
        self.input_format = tk.StringVar(value=FORMAT_LABELS["utf8"])
        self.output_format = tk.StringVar(value=FORMAT_LABELS["base64"])
        self.input_file: Path | None = None
        self.result_bytes: bytes | None = None
        self.result_text: str | None = None
        self.messages: queue.Queue[tuple] = queue.Queue()
        self.cancel_event = threading.Event()
        self.running = False
        self._build()
        self._update_mode()
        self._update_key_count()
        self.root.after(80, self._poll)

    def _build(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Malgun Gothic", 20, "bold"))
        style.configure("Section.TLabel", font=("Malgun Gothic", 11, "bold"))
        style.configure("Hint.TLabel", foreground="#607188")

        main = ttk.Frame(self.root, padding=18)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(3, weight=1)

        heading = ttk.Frame(main)
        heading.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        ttk.Label(heading, text="SEED-ECB 암복호화", style="Title.TLabel").pack(anchor="w")
        ttk.Label(heading, text="키는 정확히 16바이트 · 긴 문장과 파일은 블록 단위로 처리 · 로컬에서만 실행", style="Hint.TLabel").pack(anchor="w")

        settings = ttk.LabelFrame(main, text="방식과 키", padding=12)
        settings.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        for col in range(7):
            settings.columnconfigure(col, weight=1 if col == 3 else 0)
        ttk.Radiobutton(settings, text="암호화", value="encrypt", variable=self.mode, command=self._update_mode).grid(row=0, column=0, sticky="w", padx=(0, 12))
        ttk.Radiobutton(settings, text="복호화", value="decrypt", variable=self.mode, command=self._update_mode).grid(row=0, column=1, sticky="w", padx=(0, 16))
        ttk.Label(settings, text="키 형식").grid(row=0, column=2, sticky="e", padx=(0, 5))
        self.key_format_box = ttk.Combobox(settings, textvariable=self.key_format, state="readonly", width=16, values=list(FORMAT_LABELS.values()))
        self.key_format_box.grid(row=0, column=3, sticky="w")
        ttk.Label(settings, text="패딩").grid(row=0, column=4, sticky="e", padx=(12, 5))
        self.padding_box = ttk.Combobox(settings, textvariable=self.padding, state="readonly", width=22, values=list(PADDING_LABELS.values()))
        self.padding_box.grid(row=0, column=5, columnspan=2, sticky="w")
        ttk.Label(settings, text="비밀키").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.key_entry = ttk.Entry(settings, textvariable=self.key_text, show="●")
        self.key_entry.grid(row=1, column=1, columnspan=5, sticky="ew", pady=(10, 0), padx=(0, 7))
        self.show_button = ttk.Button(settings, text="표시", width=6, command=self._toggle_key)
        self.show_button.grid(row=1, column=6, sticky="e", pady=(10, 0))
        self.key_count = ttk.Label(settings, style="Hint.TLabel")
        self.key_count.grid(row=2, column=1, columnspan=6, sticky="w", pady=(3, 0))
        self.key_text.trace_add("write", lambda *_: self._update_key_count())
        self.key_format.trace_add("write", lambda *_: self._update_key_count())

        filebar = ttk.Frame(main)
        filebar.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        ttk.Button(filebar, text="입력 파일 선택", command=self._choose_file).pack(side="left")
        ttk.Button(filebar, text="파일 선택 해제", command=self._remove_file).pack(side="left", padx=5)
        self.file_label = ttk.Label(filebar, text="파일 없음 · 아래 입력창 사용", style="Hint.TLabel")
        self.file_label.pack(side="left", padx=8)

        panes = ttk.PanedWindow(main, orient="horizontal")
        panes.grid(row=3, column=0, sticky="nsew")
        left = ttk.Frame(panes, padding=(0, 0, 7, 0))
        right = ttk.Frame(panes, padding=(7, 0, 0, 0))
        panes.add(left, weight=1)
        panes.add(right, weight=1)
        for pane in (left, right):
            pane.columnconfigure(0, weight=1)
            pane.rowconfigure(2, weight=1)
        ttk.Label(left, text="입력", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.input_format_box = ttk.Combobox(left, textvariable=self.input_format, state="readonly", width=20)
        self.input_format_box.grid(row=1, column=0, sticky="w", pady=(5, 6))
        self.input_text = scrolledtext.ScrolledText(left, wrap="word", font=("Consolas", 10), undo=True)
        self.input_text.grid(row=2, column=0, sticky="nsew")
        ttk.Label(left, text="파일을 선택하면 입력창 대신 파일을 사용합니다.", style="Hint.TLabel").grid(row=3, column=0, sticky="w", pady=(4, 0))
        ttk.Label(right, text="결과", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.output_format_box = ttk.Combobox(right, textvariable=self.output_format, state="readonly", width=20)
        self.output_format_box.grid(row=1, column=0, sticky="w", pady=(5, 6))
        self.output_format_box.bind("<<ComboboxSelected>>", lambda _: self._render_result())
        self.output_text = scrolledtext.ScrolledText(right, wrap="word", font=("Consolas", 10), state="disabled")
        self.output_text.grid(row=2, column=0, sticky="nsew")
        self.preview_label = ttk.Label(right, text="", style="Hint.TLabel")
        self.preview_label.grid(row=3, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(main)
        actions.grid(row=4, column=0, sticky="ew", pady=(12, 4))
        self.run_button = ttk.Button(actions, text="암호화하기", command=self._start)
        self.run_button.pack(side="left")
        self.cancel_button = ttk.Button(actions, text="중지", command=self.cancel_event.set, state="disabled")
        self.cancel_button.pack(side="left", padx=5)
        ttk.Button(actions, text="결과를 입력으로", command=self._swap).pack(side="left", padx=5)
        ttk.Button(actions, text="전체 지우기", command=self._clear).pack(side="left")
        ttk.Button(actions, text="원본 바이트 저장", command=self._save_binary).pack(side="right")
        ttk.Button(actions, text="표시 결과 저장", command=self._save_text).pack(side="right", padx=5)
        ttk.Button(actions, text="결과 복사", command=self._copy).pack(side="right")

        self.progress = ttk.Progressbar(main, mode="determinate")
        self.progress.grid(row=5, column=0, sticky="ew", pady=(6, 3))
        self.status = ttk.Label(main, text="입력을 준비하세요.", style="Hint.TLabel")
        self.status.grid(row=6, column=0, sticky="w")
        ttk.Label(main, text="ECB는 같은 평문 블록이 같은 암호문 블록으로 보입니다. 기존 시스템과의 호환에 사용하세요. 0x00 패딩은 원문 끝의 0x00과 구분할 수 없습니다.", style="Hint.TLabel", wraplength=970).grid(row=7, column=0, sticky="w", pady=(9, 0))

    def _set_output(self, value: str) -> None:
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.insert("1.0", value[:PREVIEW_CHARS])
        self.output_text.configure(state="disabled")
        self.preview_label.configure(text="앞의 20만 자만 표시 · 복사/저장은 전체 결과" if len(value) > PREVIEW_CHARS else "")

    def _update_mode(self) -> None:
        if self.mode.get() == "encrypt":
            self.input_format_box.configure(values=tuple(FORMAT_LABELS[x] for x in ("utf8", "hex", "base64")))
            self.output_format_box.configure(values=tuple(FORMAT_LABELS[x] for x in ("base64", "hex")))
            self.input_format.set(FORMAT_LABELS["utf8"])
            self.output_format.set(FORMAT_LABELS["base64"])
            self.run_button.configure(text="암호화하기")
        else:
            self.input_format_box.configure(values=tuple(FORMAT_LABELS[x] for x in ("base64", "hex")))
            self.output_format_box.configure(values=tuple(FORMAT_LABELS[x] for x in ("utf8", "hex", "base64")))
            self.input_format.set(FORMAT_LABELS["base64"])
            self.output_format.set(FORMAT_LABELS["utf8"])
            self.run_button.configure(text="복호화하기")
        self.result_bytes = None
        self.result_text = None
        self._set_output("")

    def _update_key_count(self) -> None:
        if not hasattr(self, "key_count"):
            return
        try:
            count = len(decode_value(self.key_text.get(), selected_value(self.key_format.get(), FORMAT_LABELS)))
            self.key_count.configure(text=f"현재 {count}바이트 / 필요한 길이 16바이트")
        except ValueError as exc:
            self.key_count.configure(text=str(exc))

    def _toggle_key(self) -> None:
        visible = self.key_entry.cget("show") == ""
        self.key_entry.configure(show="●" if visible else "")
        self.show_button.configure(text="표시" if visible else "숨기기")

    def _choose_file(self) -> None:
        chosen = filedialog.askopenfilename(title="암복호화할 파일 선택")
        if chosen:
            self.input_file = Path(chosen)
            self.file_label.configure(text=str(self.input_file))

    def _remove_file(self) -> None:
        self.input_file = None
        self.file_label.configure(text="파일 없음 · 아래 입력창 사용")

    def _set_busy(self, value: bool) -> None:
        self.running = value
        self.run_button.configure(state="disabled" if value else "normal")
        self.cancel_button.configure(state="normal" if value else "disabled")

    def _start(self) -> None:
        if self.running:
            return
        try:
            key = parse_key(self.key_text.get(), selected_value(self.key_format.get(), FORMAT_LABELS))
            source_file = self.input_file
            if source_file is None:
                raw_text = self.input_text.get("1.0", "end-1c")
                if not raw_text:
                    raise ValueError("내용을 입력하거나 파일을 선택하세요.")
                destination_file = None
            else:
                raw_text = ""
                suffix = ".seed" if self.mode.get() == "encrypt" else ".dec"
                chosen = filedialog.asksaveasfilename(title="결과 파일 저장", initialfile=source_file.name + suffix)
                if not chosen:
                    return
                destination_file = Path(chosen)
                if source_file.resolve() == destination_file.resolve():
                    raise ValueError("원본 파일과 저장할 파일은 서로 달라야 합니다.")
                if destination_file.exists() and not messagebox.askyesno("덮어쓰기", "기존 결과 파일을 덮어쓸까요?"):
                    return
        except (ValueError, OSError) as exc:
            messagebox.showerror("입력 확인", str(exc))
            return

        self.cancel_event.clear()
        self.result_bytes = None
        self.result_text = None
        self._set_output("")
        self.progress.configure(value=0, maximum=100)
        self.status.configure(text="처리 중…")
        self._set_busy(True)
        mode = self.mode.get()
        padding = selected_value(self.padding.get(), PADDING_LABELS)
        input_format = selected_value(self.input_format.get(), FORMAT_LABELS)
        threading.Thread(
            target=self._worker,
            args=(key, mode, padding, source_file, destination_file, raw_text, input_format),
            daemon=True,
        ).start()

    def _worker(self, key, mode, padding, source_file, destination_file, raw_text, input_format) -> None:
        try:
            decrypt = mode == "decrypt"
            if source_file is not None:
                total = source_file.stat().st_size
                last_update = 0.0

                def report(done: int) -> None:
                    nonlocal last_update
                    if self.cancel_event.is_set():
                        raise RuntimeError("작업을 중지했습니다.")
                    now = time.monotonic()
                    if now - last_update >= 0.12 or done == total:
                        self.messages.put(("progress", done, total))
                        last_update = now

                read_count, written_count = convert_file(
                    source_file, destination_file, key, decrypt=decrypt, padding=padding, progress=report
                )
                self.messages.put(("file_done", destination_file, read_count, written_count))
            else:
                data = decode_value(raw_text, input_format)
                if self.cancel_event.is_set():
                    raise RuntimeError("작업을 중지했습니다.")
                source = io.BytesIO(data)
                destination = io.BytesIO()

                def report(done: int) -> None:
                    if self.cancel_event.is_set():
                        raise RuntimeError("작업을 중지했습니다.")
                    self.messages.put(("progress", done, len(data)))

                transform_stream(source, destination, key, decrypt=decrypt, padding=padding, progress=report)
                self.messages.put(("text_done", destination.getvalue(), len(data)))
        except Exception as exc:
            self.messages.put(("error", str(exc)))

    def _poll(self) -> None:
        try:
            while True:
                event = self.messages.get_nowait()
                kind = event[0]
                if kind == "progress":
                    done, total = event[1:]
                    self.progress.configure(value=100 * done / total if total else 0)
                    self.status.configure(text=f"처리 중 · {done:,} / {total:,}바이트")
                elif kind == "file_done":
                    path, read_count, written_count = event[1:]
                    self.progress.configure(value=100)
                    self.status.configure(text=f"완료 · {read_count:,} → {written_count:,}바이트 · {path}")
                    self._set_busy(False)
                elif kind == "text_done":
                    self.result_bytes, input_count = event[1:]
                    self.progress.configure(value=100)
                    self.status.configure(text=f"완료 · 입력 {input_count:,}바이트 / 결과 {len(self.result_bytes):,}바이트")
                    self._render_result()
                    self._set_busy(False)
                elif kind == "error":
                    self.status.configure(text=event[1])
                    self._set_busy(False)
                    messagebox.showerror("처리 실패", event[1])
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _render_result(self) -> None:
        if self.result_bytes is None:
            return
        try:
            self.result_text = encode_value(self.result_bytes, selected_value(self.output_format.get(), FORMAT_LABELS))
            self._set_output(self.result_text)
        except ValueError as exc:
            self.result_text = None
            self._set_output("")
            self.status.configure(text=str(exc))

    def _swap(self) -> None:
        if self.running or self.result_text is None:
            return
        fmt, content = self.output_format.get(), self.result_text
        self._remove_file()
        self.mode.set("decrypt" if self.mode.get() == "encrypt" else "encrypt")
        self._update_mode()
        self.input_format.set(fmt)
        self.input_text.delete("1.0", "end")
        self.input_text.insert("1.0", content)
        self.status.configure(text="결과를 입력으로 옮겼습니다.")

    def _clear(self) -> None:
        if self.running:
            self.cancel_event.set()
        self.key_text.set("")
        self.input_text.delete("1.0", "end")
        self._remove_file()
        self.result_bytes = None
        self.result_text = None
        self._set_output("")
        self.status.configure(text="입력과 결과를 지웠습니다.")

    def _copy(self) -> None:
        if self.result_text is None:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.result_text)
        self.status.configure(text="전체 결과를 클립보드에 복사했습니다.")

    def _save_text(self) -> None:
        if self.result_text is None:
            return
        chosen = filedialog.asksaveasfilename(title="표시 결과 저장", defaultextension=".txt", initialfile="seed-ecb-result.txt")
        if chosen:
            Path(chosen).write_text(self.result_text, encoding="utf-8")
            self.status.configure(text=f"저장했습니다 · {chosen}")

    def _save_binary(self) -> None:
        if self.result_bytes is None:
            return
        chosen = filedialog.asksaveasfilename(title="원본 바이트 저장", defaultextension=".bin", initialfile="seed-ecb-result.bin")
        if chosen:
            Path(chosen).write_bytes(self.result_bytes)
            self.status.configure(text=f"저장했습니다 · {chosen}")


def cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="SEED-128 ECB 파일 암복호화. 키는 실행 시 별도로 입력합니다.")
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--key-format", choices=("utf8", "hex", "base64"), default="utf8")
    parser.add_argument("--padding", choices=("pkcs7", "none", "zero"), default="pkcs7")
    parser.add_argument("--overwrite", action="store_true", help="기존 출력 파일 덮어쓰기")
    args = parser.parse_args(argv)
    if args.output.exists() and not args.overwrite:
        parser.error("출력 파일이 이미 있습니다. 다른 이름이나 --overwrite를 지정하세요.")
    try:
        key = parse_key(getpass.getpass("SEED 키: "), args.key_format)
        read_count, written_count = convert_file(
            args.input, args.output, key, decrypt=args.operation == "decrypt", padding=args.padding
        )
        print(f"완료: {read_count:,} → {written_count:,}바이트 · {args.output}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"오류: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        raise SystemExit(cli(sys.argv[2:]))
    if tk is None:
        raise SystemExit("화면을 열려면 Python tkinter가 필요합니다. 파일 작업은 --cli 옵션으로 실행할 수 있습니다.")
    root = tk.Tk()
    SeedWindow(root)
    root.mainloop()
