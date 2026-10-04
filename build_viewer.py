"""Embed the readable triage source into the offline, single-file viewer."""
from pathlib import Path

root = Path(__file__).resolve().parent
page = root / "index.html"
html = page.read_text(encoding="utf-8")
start = "<!-- triage-enhancement:start -->"
end = "<!-- triage-enhancement:end -->"
if start in html:
    before, rest = html.split(start, 1)
    _, after = rest.split(end, 1)
    html = before + after
css = (root / "triage.css").read_text(encoding="utf-8")
js = (root / "triage.js").read_text(encoding="utf-8")
addition = f"{start}\n<style>\n{css}</style>\n<script>\n{js}</script>\n{end}\n"
html = html.replace("</body></html>", addition + "</body></html>")
page.write_text(html, encoding="utf-8")
