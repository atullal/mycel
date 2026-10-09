"""Run video-probe.html in WebKitGTK (the Linux app's web view) with the same
settings the app turns on (camera capture allowed, getUserMedia enabled) and
a mock camera, and print what it found. Exits 1 if no video came out.

    xvfb-run python3 scripts/ci/video-probe-gtk.py
"""

import json
import pathlib
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("WebKit2", "4.1")
from gi.repository import GLib, Gtk, WebKit2  # noqa: E402

page = (pathlib.Path(__file__).parent / "video-probe.html").read_text()
result = {}

view = WebKit2.WebView()
settings = view.get_settings()
settings.set_enable_media_stream(True)
settings.set_enable_mock_capture_devices(True)


def on_permission(_view, request):
    if isinstance(request, WebKit2.UserMediaPermissionRequest):
        request.allow()
        return True
    return False


def on_title(v, _param):
    title = v.get_title() or ""
    if title.startswith("probe "):
        result.update(json.loads(title[len("probe "):]))
        Gtk.main_quit()


def give_up():
    result.setdefault("error", "timed out")
    Gtk.main_quit()
    return False


view.connect("permission-request", on_permission)
view.connect("notify::title", on_title)
window = Gtk.Window()
window.add(view)
window.show_all()
# localhost is a secure context, which getUserMedia and WebCodecs need
view.load_html(page, "http://localhost/")
GLib.timeout_add_seconds(60, give_up)
Gtk.main()

version = f"{WebKit2.get_major_version()}.{WebKit2.get_minor_version()}.{WebKit2.get_micro_version()}"
print(f"WebKitGTK {version}: {json.dumps(result, indent=2)}")
sys.exit(0 if result.get("ok") else 1)
