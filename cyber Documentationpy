#!/usr/bin/env python3
"""
Cybersecurity Documentation Tool v4.0 - Enhanced Edition
- RGB UI
- AI Chatbox
- Auto-Reports
- Drive Upload
- Safer Capture
- Model Fallbacks
- Model Testing
- RAM Awareness
- Log Panel
- OCR Debug Tab
- Command History Tab
- Live Watch Mode
- Multi-Frame Analysis
"""

import sys
import subprocess
import importlib.util as iu
import platform as pf
import json
import os
import base64
import time
import shutil
import traceback
from datetime import datetime as dt
from pathlib import Path as P

# ============================================================
# ERROR LOGGING
# ============================================================

ERROR_LOG = P.home() / '.cybersec' / 'error.log'


def log_error(msg):
    """Write errors to ~/.cybersec/error.log"""
    try:
        ERROR_LOG.parent.mkdir(exist_ok=True)
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*70 + "\n")
            f.write(f"[{dt.now()}] ERROR\n")
            f.write(f"{msg}\n")
            f.write(traceback.format_exc())
    except Exception:
        pass


print("=" * 70)
print("🔒 CYBERSEC TOOL v4.0 - STARTING...")
print("=" * 70 + "\n")


# ============================================================
# PACKAGE INSTALLER
# ============================================================

def ensure_package(pkg, imp=None):
    """Ensure a Python package is installed."""
    mod_name = imp or pkg
    if iu.find_spec(mod_name) is None:
        print(f"Installing {pkg}...", end=" ", flush=True)
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "-q", pkg],
                timeout=180,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if iu.find_spec(mod_name) is None:
                print("✗ (module still not found)")
                log_error(f"Package {pkg} installed but module {mod_name} not found")
            else:
                print("✓")
        except Exception as e:
            print("✗ (run: pip install " + pkg + ")")
            log_error(f"Failed to install package {pkg}: {e}")


# Core required packages
for p, i in [
    ("PyQt6", "PyQt6"),
    ("requests", "requests"),
    ("Pillow", "PIL"),
    ("mss", "mss"),
    ("opencv-python", "cv2"),
    ("numpy", "numpy"),
    ("psutil", "psutil"),
]:
    ensure_package(p, i)


# Optional packages (OCR + Google Drive)
for p, i in [
    ("google-auth", "google.auth"),
    ("google-auth-oauthlib", "google_auth_oauthlib"),
    ("google-api-python-client", "googleapiclient"),
    ("google-auth-httplib2", "google_auth_httplib2"),
    ("pytesseract", "pytesseract"),
]:
    try:
        ensure_package(p, i)
    except Exception as e:
        log_error(f"Optional package install failed for {p}: {e}")


print("\n" + "=" * 70)
print("✓ PACKAGES READY")
print("=" * 70 + "\n")


# ============================================================
# IMPORTS
# ============================================================

try:
    import requests as rq
    import mss
    import cv2
    import numpy as np
    import psutil
    from PIL import Image as Im

    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QLabel, QPushButton, QTextEdit, QListWidget, QLineEdit, QSplitter,
        QTabWidget, QDialog, QFormLayout, QGroupBox, QSpinBox, QComboBox,
        QCheckBox, QFileDialog, QMessageBox, QStatusBar
    )
    from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
    from PyQt6.QtGui import QImage, QPixmap

    print("Core imports successful ✓")

except Exception as e:
    print(f"CRITICAL ERROR: Import failed - {e}")
    log_error(f"Import error: {e}")
    input("Press Enter to exit...")
    sys.exit(1)


# ============================================================
# OPTIONAL IMPORTS (OCR + DRIVE)
# ============================================================

# OCR
try:
    import pytesseract as ts
    ts.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
    OCR = True
except Exception as e:
    OCR = False
    print(f"OCR not available: {e}")
    log_error(f"OCR import: {e}")

# Google Drive
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    DRIVE = True
except Exception as e:
    DRIVE = False
    print(f"Google Drive not available: {e}")
    log_error(f"Drive import: {e}")


# ============================================================
# DIRECTORIES
# ============================================================

H = P.home() / '.cybersec'
CF = H / 'cfg.json'
SS = H / 'sess'
TK = H / 'tok.json'
RPT_DIR = H / 'reports'
LOG_DIR = H / 'logs'

H.mkdir(exist_ok=True)
SS.mkdir(exist_ok=True)
RPT_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)


# ============================================================
# GOOGLE DRIVE UPLOADER
# ============================================================

class DriveUploader:
    def __init__(self):
        self.service = None
        self.folder_id = None
        self.authenticated = False

    def authenticate(self, creds_path):
        if not DRIVE:
            return False, "Google libraries not installed"

        try:
            SCOPES = ['https://www.googleapis.com/auth/drive.file']
            creds = None

            if TK.exists():
                creds = Credentials.from_authorized_user_file(str(TK), SCOPES)

            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
                    creds = flow.run_local_server(port=0)

                TK.write_text(creds.to_json(), encoding='utf-8')

            self.service = build('drive', 'v3', credentials=creds)
            self.authenticated = True
            return True, "✓ Authenticated"

        except Exception as e:
            log_error(f"Drive auth error: {e}")
            return False, str(e)

    def upload_file(self, file_path, folder_id=None):
        if not DRIVE or not self.authenticated:
            return False, "Not authenticated"

        try:
            meta = {'name': P(file_path).name}
            if folder_id:
                meta['parents'] = [folder_id]

            media = MediaFileUpload(file_path, resumable=True)

            f = (
                self.service.files()
                .create(body=meta, media_body=media, fields='webViewLink')
                .execute()
            )

            return True, f.get('webViewLink', 'Uploaded')

        except Exception as e:
            log_error(f"Drive upload error: {e}")
            return False, str(e)


# ============================================================
# SCREEN CAPTURE THREAD (SAFE VERSION)
# ============================================================

class ScreenThread(QThread):
    frame = pyqtSignal(object)
    fps = pyqtSignal(float)
    error = pyqtSignal(str)

    def __init__(self, target_fps=30):
        super().__init__()
        self.running = False
        self.target_fps = max(5, min(60, target_fps))

    def run(self):
        self.running = True
        try:
            with mss.mss() as sct:
                try:
                    mon = sct.monitors[1] if len(sct.monitors) > 1 else sct.monitors[0]
                except Exception as e:
                    log_error(f"Monitor selection error: {e}")
                    self.error.emit("Failed to select monitor for capture.")
                    self.running = False
                    return

                cnt, t0 = 0, time.time()
                delay = 1.0 / self.target_fps

                while self.running:
                    loop_start = time.time()
                    try:
                        img = sct.grab(mon)
                        frm = cv2.cvtColor(np.array(img), cv2.COLOR_BGRA2BGR)
                        self.frame.emit(frm.copy())
                        cnt += 1

                        if cnt % 30 == 0:
                            elapsed = time.time() - t0
                            if elapsed > 0:
                                self.fps.emit(cnt / elapsed)

                    except Exception as e:
                        log_error(f"Screen capture frame error: {e}")
                        time.sleep(0.1)
                        continue

                    spent = time.time() - loop_start
                    if spent < delay:
                        time.sleep(delay - spent)

        except Exception as e:
            log_error(f"Screen thread error: {e}")
            self.error.emit(f"Screen capture failed: {e}")

        finally:
            self.running = False

    def stop(self):
        self.running = False


# ============================================================
# AI ANALYSIS THREAD (RAM-AWARE + FALLBACKS + OCR DEBUG + MULTI-FRAME)
# ============================================================

class AIThread(QThread):
    done = pyqtSignal(str, dict)
    error = pyqtSignal(str)
    log = pyqtSignal(str)
    ocr_debug = pyqtSignal(str)

    def __init__(self, url, model, frame=None, ocr=False, extra_prompt=None, multi_frames=None):
        super().__init__()
        self.url = url
        self.model = model
        self.frame = frame              # single frame (numpy)
        self.ocr = ocr
        self.extra_prompt = extra_prompt or ""
        self.multi_frames = multi_frames  # list of {"frame": np.array, "timestamp": str}

    # ------------------------------------------------------------
    # RAM CHECK
    # ------------------------------------------------------------
    def model_too_large(self, model_name):
        sizes = {
            "llama3.2-vision": 27,
            "llama3.2": 4,
            "llama2": 8,
            "qwen2.5-coder:7b": 10,
            "wizardcoder:13b-python": 16,
            "gemma3:4b": 6,
        }

        need = sizes.get(model_name.lower(), 4)
        have = psutil.virtual_memory().available / (1024**3)

        return need > have, need, have

    # ------------------------------------------------------------
    # JSON EXTRACTION
    # ------------------------------------------------------------
    def extract_json(self, text):
        try:
            s, e = text.find("{"), text.rfind("}") + 1
            if s >= 0 and e > s:
                return json.loads(text[s:e])
            return {"raw": text}
        except Exception:
            return {"raw": text}

    # ------------------------------------------------------------
    # MAIN RUN
    # ------------------------------------------------------------
    def run(self):
        try:
            # ----------------------------------------------------
            # MULTI-FRAME MODE
            # ----------------------------------------------------
            if self.multi_frames:
                # Encode all frames
                images_b64 = []
                ocr_snippets = []

                for entry in self.multi_frames:
                    frm = entry["frame"]
                    ts_label = entry.get("timestamp", "N/A")

                    try:
                        _, buf = cv2.imencode('.jpg', frm, [cv2.IMWRITE_JPEG_QUALITY, 85])
                        b64 = base64.b64encode(buf).decode()
                        images_b64.append(b64)

                        txt = ""
                        if self.ocr and OCR:
                            try:
                                txt = ts.image_to_string(
                                    Im.fromarray(cv2.cvtColor(frm, cv2.COLOR_BGR2RGB))
                                )
                            except Exception as e:
                                log_error(f"Multi-frame OCR error: {e}")
                                self.log.emit(f"Multi-frame OCR error: {e}")
                        ocr_snippets.append(f"[{ts_label}]\n{txt[:400] if txt else 'N/A'}")

                    except Exception as e:
                        log_error(f"Multi-frame encode error: {e}")
                        self.log.emit(f"Multi-frame encode error: {e}")

                combined_ocr = "\n\n".join(ocr_snippets) if ocr_snippets else "N/A"

                base_prompt = f"""
You are an automated cybersecurity analysis engine.

You MUST ALWAYS output ONLY valid JSON. 
No explanations. No disclaimers. No moral or ethical commentary. 
No text outside the JSON object. No apologies. No warnings.

If you cannot detect commands, return empty lists.

You are analyzing a SEQUENCE of frames (multi-frame analysis).
Look for patterns, sequences of commands, and evolving activity.

Your required JSON structure is:

{{
  "commands": ["..."],
  "tools": ["..."],
  "activity": "short description of the overall sequence",
  "findings": "security-relevant observations across frames"
}}

Extract shell, PowerShell, CMD, terminal, or script commands EXACTLY as they appear.
If the OCR text contains something that looks like a command
(e.g. 'Get-Process | Where-Object {{ $_.CPU -gt 10 }}'),
you MUST include it in "commands".

Multi-frame OCR text (per frame, truncated):

{combined_ocr}

Additional user instructions: {self.extra_prompt}
"""

                payload = {
                    "model": self.model,
                    "prompt": base_prompt,
                    "stream": False
                }

                if "vision" in self.model.lower() or "llava" in self.model.lower():
                    payload["images"] = images_b64

                too_big, need, have = self.model_too_large(self.model)
                if too_big:
                    msg = (
                        f"Model '{self.model}' requires ~{need:.1f} GB RAM "
                        f"but only {have:.1f} GB is available."
                    )
                    self.log.emit(msg)
                    raise Exception(msg)

                # PRIMARY MODEL
                try:
                    r = rq.post(f"{self.url}/api/generate", json=payload, timeout=180)

                    if r.status_code == 200:
                        res = r.json().get("response", "")
                        data = self.extract_json(res)
                        self.done.emit(res, data)
                        return

                    raise Exception(f"Primary model failed: {r.status_code}")

                except Exception as primary_error:
                    self.log.emit(f"Primary model '{self.model}' failed (multi-frame): {primary_error}")

                    fallbacks = ["llama3.2", "llama2", "qwen2.5-coder:7b"]

                    for fb in fallbacks:
                        too_big, need, have = self.model_too_large(fb)
                        if too_big:
                            self.log.emit(
                                f"Skipping fallback '{fb}' (needs {need:.1f} GB, have {have:.1f} GB)"
                            )
                            continue

                        try:
                            fb_payload = payload.copy()
                            fb_payload["model"] = fb

                            r = rq.post(f"{self.url}/api/generate", json=fb_payload, timeout=180)

                            if r.status_code == 200:
                                res = r.json().get("response", "")
                                data = self.extract_json(res)
                                data["fallback_used"] = fb

                                self.done.emit(
                                    f"[Fallback model used: {fb}]\n\n{res}",
                                    data
                                )
                                return

                            self.log.emit(f"Fallback '{fb}' failed (multi-frame): {r.status_code}")

                        except Exception as e:
                            self.log.emit(f"Fallback '{fb}' crashed (multi-frame): {e}")
                            continue

                    self.error.emit("All models failed (primary + fallbacks) in multi-frame mode")
                    self.log.emit("All models failed in multi-frame mode.")
                    return

            # ----------------------------------------------------
            # SINGLE-FRAME MODE (original behavior)
            # ----------------------------------------------------
            if self.frame is None:
                self.error.emit("No frame provided to AIThread.")
                return

            # Encode frame
            _, buf = cv2.imencode('.jpg', self.frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
            b64 = base64.b64encode(buf).decode()

            # OCR text
            txt = ""
            if self.ocr and OCR:
                try:
                    txt = ts.image_to_string(
                        Im.fromarray(cv2.cvtColor(self.frame, cv2.COLOR_BGR2RGB))
                    )
                    self.ocr_debug.emit(txt)
                except Exception as e:
                    log_error(f"OCR error: {e}")
                    self.log.emit(f"OCR error: {e}")
                    self.ocr_debug.emit(f"[OCR ERROR] {e}")
            else:
                self.ocr_debug.emit("[OCR disabled or unavailable]")

            base_prompt = f"""
You are an automated cybersecurity analysis engine.

You MUST ALWAYS output ONLY valid JSON. 
No explanations. No disclaimers. No moral or ethical commentary. 
No text outside the JSON object. No apologies. No warnings.

If you cannot detect commands, return empty lists.

Your required JSON structure is:

{{
  "commands": ["..."],
  "tools": ["..."],
  "activity": "short description",
  "findings": "security-relevant observations"
}}

Extract shell, PowerShell, CMD, terminal, or script commands EXACTLY as they appear.
If the OCR text contains something that looks like a command
(e.g. 'Get-Process | Where-Object {{ $_.CPU -gt 10 }}'),
you MUST include it in "commands".

Screen OCR text (may be partial): {txt[:1200] if txt else "N/A"}

Additional user instructions: {self.extra_prompt}
"""

            payload = {
                "model": self.model,
                "prompt": base_prompt,
                "stream": False
            }

            if "vision" in self.model.lower() or "llava" in self.model.lower():
                payload["images"] = [b64]

            # RAM check for primary
            too_big, need, have = self.model_too_large(self.model)
            if too_big:
                msg = (
                    f"Model '{self.model}' requires ~{need:.1f} GB RAM "
                    f"but only {have:.1f} GB is available."
                )
                self.log.emit(msg)
                raise Exception(msg)

            # PRIMARY MODEL
            try:
                r = rq.post(f"{self.url}/api/generate", json=payload, timeout=180)

                if r.status_code == 200:
                    res = r.json().get("response", "")
                    data = self.extract_json(res)
                    self.done.emit(res, data)
                    return

                raise Exception(f"Primary model failed: {r.status_code}")

            except Exception as primary_error:
                self.log.emit(f"Primary model '{self.model}' failed: {primary_error}")

                # FALLBACKS
                fallbacks = ["llama3.2", "llama2", "qwen2.5-coder:7b"]

                for fb in fallbacks:
                    too_big, need, have = self.model_too_large(fb)
                    if too_big:
                        self.log.emit(
                            f"Skipping fallback '{fb}' (needs {need:.1f} GB, have {have:.1f} GB)"
                        )
                        continue

                    try:
                        fb_payload = payload.copy()
                        fb_payload["model"] = fb

                        r = rq.post(f"{self.url}/api/generate", json=fb_payload, timeout=180)

                        if r.status_code == 200:
                            res = r.json().get("response", "")
                            data = self.extract_json(res)
                            data["fallback_used"] = fb

                            self.done.emit(
                                f"[Fallback model used: {fb}]\n\n{res}",
                                data
                            )
                            return

                        self.log.emit(f"Fallback '{fb}' failed: {r.status_code}")

                    except Exception as e:
                        self.log.emit(f"Fallback '{fb}' crashed: {e}")
                        continue

                self.error.emit("All models failed (primary + fallbacks)")
                self.log.emit("All models failed.")

        except Exception as ex:
            log_error(f"AI analysis error: {ex}")
            self.log.emit(f"AIThread exception: {ex}")
            self.error.emit(str(ex))


# ============================================================
# VIDEO RECORDER
# ============================================================

class Recorder:
    def __init__(self):
        self.rec = False
        self.writer = None
        self.path = None

    def start(self, path, fps, res):
        try:
            self.path = path
            self.writer = cv2.VideoWriter(
                str(path),
                cv2.VideoWriter_fourcc(*"mp4v"),
                fps,
                res
            )

            if not self.writer.isOpened():
                log_error(f"VideoWriter failed to open: {path}")
                return False

            self.rec = True
            return True

        except Exception as e:
            log_error(f"Recording start error: {e}")
            return False

    def write(self, frame):
        if self.rec and self.writer:
            try:
                self.writer.write(frame)
            except Exception as e:
                log_error(f"Recorder write error: {e}")

    def stop(self):
        if self.writer:
            try:
                self.writer.release()
            except Exception as e:
                log_error(f"Recorder release error: {e}")

        self.rec = False
        self.writer = None
        return self.path
        # ============================================================
# SETTINGS DIALOG
# ============================================================

class CyberSettings(QDialog):
    def __init__(self, parent=None, cfg=None):
        super().__init__(parent)
        self.setWindowTitle("Cybersecurity Tool Settings")
        self.cfg = cfg or {}

        lay = QVBoxLayout(self)

        # --- Ollama URL ---
        gb1 = QGroupBox("Ollama Server")
        f1 = QFormLayout()
        self.url = QLineEdit(self.cfg.get("url", "http://localhost:11434"))
        f1.addRow("Server URL:", self.url)
        gb1.setLayout(f1)
        lay.addWidget(gb1)

        # --- Model selection ---
        gb2 = QGroupBox("AI Model")
        f2 = QFormLayout()

        self.model = QComboBox()
        self.model.addItems([
            "llama3.2-vision",
            "llama3.2",
            "llama2",
            "qwen2.5-coder:7b",
            "wizardcoder:13b-python",
            "gemma3:4b"
        ])
        if self.cfg.get("model") in [self.model.itemText(i) for i in range(self.model.count())]:
            self.model.setCurrentText(self.cfg.get("model"))

        f2.addRow("Model:", self.model)

        # RAM display
        self.ram_lbl = QLabel()
        self.update_ram_label()
        f2.addRow("System RAM:", self.ram_lbl)

        # Test model button
        self.btn_test = QPushButton("Test Model")
        self.btn_test.clicked.connect(self.test_model)
        f2.addRow(self.btn_test)

        gb2.setLayout(f2)
        lay.addWidget(gb2)

        # --- FPS ---
        gb3 = QGroupBox("Screen Capture")
        f3 = QFormLayout()
        self.fps = QSpinBox()
        self.fps.setRange(5, 60)
        self.fps.setValue(self.cfg.get("fps", 30))
        f3.addRow("FPS:", self.fps)
        gb3.setLayout(f3)
        lay.addWidget(gb3)

        # --- OCR ---
        self.ocr = QCheckBox("Enable OCR (Tesseract)")
        self.ocr.setChecked(self.cfg.get("ocr", True))
        lay.addWidget(self.ocr)

        # --- Drive ---
        self.drive = QCheckBox("Enable Google Drive Upload")
        self.drive.setChecked(self.cfg.get("drive", False))
        lay.addWidget(self.drive)

        # --- Buttons ---
        hb = QHBoxLayout()
        ok = QPushButton("Save")
        ok.clicked.connect(self.accept)
        hb.addWidget(ok)

        cancel = QPushButton("Cancel")
        cancel.clicked.connect(self.reject)
        hb.addWidget(cancel)

        lay.addLayout(hb)

    def update_ram_label(self):
        ram_gb = psutil.virtual_memory().total / (1024**3)
        self.ram_lbl.setText(f"{ram_gb:.1f} GB")

    def test_model(self):
        model = self.model.currentText()
        ram = psutil.virtual_memory().available / (1024**3)

        need_map = {
            "llama3.2-vision": 27,
            "llama3.2": 4,
            "llama2": 8,
            "qwen2.5-coder:7b": 10,
            "wizardcoder:13b-python": 16,
            "gemma3:4b": 6,
        }

        need = need_map.get(model, 4)

        if ram < need:
            QMessageBox.warning(
                self,
                "Model Too Large",
                f"Model '{model}' needs ~{need} GB RAM.\n"
                f"Available: {ram:.1f} GB.\n\n"
                "This model may fail or crash Ollama."
            )
        else:
            QMessageBox.information(
                self,
                "Model OK",
                f"Model '{model}' should run.\n"
                f"Needs ~{need} GB, available {ram:.1f} GB."
            )

    def get(self):
        return {
            "url": self.url.text().strip(),
            "model": self.model.currentText(),
            "fps": self.fps.value(),
            "ocr": self.ocr.isChecked(),
            "drive": self.drive.isChecked(),
        }


# ============================================================
# RGB LABEL
# ============================================================

class RGBLabel(QLabel):
    def __init__(self, text="", speed=8):
        super().__init__(text)
        self.h = 0
        self.speed = speed
        self.setStyleSheet("font-weight: bold; font-size: 16px;")
        self.t = QTimer()
        self.t.timeout.connect(self.tick)
        self.t.start(50)

    def tick(self):
        self.h = (self.h + self.speed) % 360
        self.setStyleSheet(
            f"color: hsl({self.h}, 100%, 60%); font-weight: bold; font-size: 16px;"
        )


# ============================================================
# MAIN WINDOW
# ============================================================

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Cybersecurity Documentation Tool v4.0")
        self.resize(1500, 950)

        self.cfg = self.load_cfg()
        self.drive = DriveUploader()
        self.st = ScreenThread(self.cfg.get("fps", 30))
        self.st.frame.connect(self.on_frame)
        self.st.fps.connect(self.on_fps)
        self.st.error.connect(self.on_capture_error)

        self.rec = Recorder()

        # NEW: command history + frame buffer + live watch
        self.command_history = []   # list of dicts {command, timestamp, source}
        self.frame_buffer = []      # list of dicts {frame, timestamp}
        self.max_frame_buffer = 50

        self.live_timer = QTimer(self)
        self.live_timer.timeout.connect(self.on_live_tick)
        self.live_running = False

        self.build_ui()
        self.st.start()

    # CONFIG
    def load_cfg(self):
        if CF.exists():
            try:
                return json.loads(CF.read_text())
            except Exception as e:
                log_error(f"Config load error: {e}")
        return {
            "url": "http://localhost:11434",
            "model": "llama3.2-vision",
            "fps": 30,
            "ocr": True,
            "drive": False,
        }

    def save_cfg(self):
        try:
            CF.write_text(json.dumps(self.cfg, indent=2))
        except Exception as e:
            log_error(f"Config save error: {e}")

    # UI BUILD
    def build_ui(self):
        w = QWidget()
        self.setCentralWidget(w)
        lay = QVBoxLayout(w)

        self.hdr = RGBLabel("CYBERSECURITY DOCUMENTATION TOOL v4.0")
        self.hdr.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(self.hdr)

        sp = QSplitter(Qt.Orientation.Horizontal)
        lay.addWidget(sp, 1)

        # LEFT
        left = QWidget()
        llay = QVBoxLayout(left)

        self.prev = QLabel("Waiting for screen...")
        self.prev.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.prev.setStyleSheet("background: #000; color: #0f0;")
        llay.addWidget(self.prev, 1)

        self.fps_lbl = QLabel("FPS: --")
        self.fps_lbl.setStyleSheet("color: cyan; font-weight: bold;")
        llay.addWidget(self.fps_lbl)

        sp.addWidget(left)

        # RIGHT TABS
        self.tabs = QTabWidget()
        sp.addWidget(self.tabs)

        # AI TAB
        self.tab_ai = QWidget()
        tlay = QVBoxLayout(self.tab_ai)

        self.ai_out = QTextEdit()
        self.ai_out.setReadOnly(True)
        self.ai_out.setStyleSheet("background: #111; color: #0f0;")
        tlay.addWidget(self.ai_out, 1)

        self.prompt = QLineEdit()
        self.prompt.setPlaceholderText("Optional extra prompt...")
        tlay.addWidget(self.prompt)

        hb = QHBoxLayout()
        self.btn_an = QPushButton("Analyze Frame")
        self.btn_an.clicked.connect(self.analyze)
        hb.addWidget(self.btn_an)

        self.btn_sum = QPushButton("Generate Summary")
        self.btn_sum.clicked.connect(self.gen_summary)
        hb.addWidget(self.btn_sum)

        # NEW: Live Watch controls
        self.btn_live = QPushButton("Start Live Watch")
        self.btn_live.setCheckable(True)
        self.btn_live.clicked.connect(self.toggle_live)
        hb.addWidget(self.btn_live)

        self.live_interval = QSpinBox()
        self.live_interval.setRange(1, 60)
        self.live_interval.setValue(5)
        self.live_interval.valueChanged.connect(self.on_live_interval_changed)
        hb.addWidget(QLabel("Live (sec):"))
        hb.addWidget(self.live_interval)

        # NEW: Multi-frame controls
        self.btn_multi = QPushButton("Analyze Last N Frames")
        self.btn_multi.clicked.connect(self.multi_frame_analyze)
        hb.addWidget(self.btn_multi)

        self.multi_n = QSpinBox()
        self.multi_n.setRange(2, 50)
        self.multi_n.setValue(10)
        hb.addWidget(QLabel("N:"))
        hb.addWidget(self.multi_n)

        tlay.addLayout(hb)
        self.tabs.addTab(self.tab_ai, "AI Analysis")

        # COMMANDS TAB (current session commands list)
        self.tab_cmd = QWidget()
        cl = QVBoxLayout(self.tab_cmd)

        self.cmd_list = QListWidget()
        cl.addWidget(self.cmd_list)

        self.tabs.addTab(self.tab_cmd, "Commands")

        # NEW: COMMAND HISTORY TAB (with timestamps + source)
        self.tab_hist = QWidget()
        hl = QVBoxLayout(self.tab_hist)
        self.hist_list = QListWidget()
        hl.addWidget(self.hist_list)
        self.tabs.addTab(self.tab_hist, "Command History")

        # REPORT TAB
        self.tab_rpt = QWidget()
        rl = QVBoxLayout(self.tab_rpt)

        self.rpt = QTextEdit()
        self.rpt.setStyleSheet("background: #111; color: #0f0;")
        rl.addWidget(self.rpt, 1)

        hb2 = QHBoxLayout()
        self.btn_save = QPushButton("Save Report")
        self.btn_save.clicked.connect(self.save_report)
        hb2.addWidget(self.btn_save)

        self.btn_drive = QPushButton("Upload to Drive")
        self.btn_drive.clicked.connect(self.upload_drive)
        hb2.addWidget(self.btn_drive)

        rl.addLayout(hb2)
        self.tabs.addTab(self.tab_rpt, "Report")

        # LOG TAB
        self.tab_log = QWidget()
        ll = QVBoxLayout(self.tab_log)

        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setStyleSheet("background: #111; color: #ff0;")
        ll.addWidget(self.log_box)

        self.tabs.addTab(self.tab_log, "Logs")

        # OCR TAB
        self.tab_ocr = QWidget()
        ocl = QVBoxLayout(self.tab_ocr)

        self.ocr_box = QTextEdit()
        self.ocr_box.setReadOnly(True)
        self.ocr_box.setStyleSheet("background: #111; color: #0ff;")
        ocl.addWidget(self.ocr_box)

        self.tabs.addTab(self.tab_ocr, "OCR Text")

        self.sb = QStatusBar()
        self.setStatusBar(self.sb)

        self.create_menu()
            # FRAME HANDLING
    def on_frame(self, frm):
        try:
            h, w, _ = frm.shape
            q = QImage(frm.data, w, h, QImage.Format.Format_BGR888)
            self.prev.setPixmap(QPixmap.fromImage(q).scaled(
                self.prev.width(),
                self.prev.height(),
                Qt.AspectRatioMode.KeepAspectRatio
            ))

            if self.rec.rec:
                self.rec.write(frm)

            self.last_frame = frm

            # NEW: push into frame buffer for multi-frame analysis
            self.push_frame_buffer(frm)

        except Exception as e:
            log_error(f"Frame update error: {e}")

    def push_frame_buffer(self, frm):
        try:
            entry = {
                "frame": frm.copy(),
                "timestamp": dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.frame_buffer.append(entry)
            if len(self.frame_buffer) > self.max_frame_buffer:
                self.frame_buffer.pop(0)
        except Exception as e:
            log_error(f"Frame buffer error: {e}")

    def on_fps(self, v):
        self.fps_lbl.setText(f"FPS: {v:.1f}")

    def on_capture_error(self, msg):
        self.sb.showMessage(msg, 5000)

    # AI ANALYSIS (single frame)
    def analyze(self):
        if not hasattr(self, "last_frame"):
            self.sb.showMessage("No frame yet", 5000)
            return

        url = self.cfg.get("url", "http://localhost:11434")
        model = self.cfg.get("model", "llama3.2-vision")
        extra = self.prompt.text().strip()

        self.ai_out.append("\n--- Analyzing frame... ---\n")

        self.ai = AIThread(
            url=url,
            model=model,
            frame=self.last_frame,
            ocr=self.cfg.get("ocr", True),
            extra_prompt=extra
        )
        self.ai.done.connect(self.on_ai_done)
        self.ai.error.connect(self.on_ai_error)
        self.ai.log.connect(self.on_ai_log)
        self.ai.ocr_debug.connect(self.on_ocr_debug)
        self.ai.start()

    # NEW: LIVE WATCH
    def toggle_live(self, checked):
        self.live_running = checked
        if checked:
            self.btn_live.setText("Stop Live Watch")
            self.live_timer.start(self.live_interval.value() * 1000)
            self.sb.showMessage("Live watch started", 3000)
        else:
            self.btn_live.setText("Start Live Watch")
            self.live_timer.stop()
            self.sb.showMessage("Live watch stopped", 3000)

    def on_live_interval_changed(self, val):
        if self.live_running:
            self.live_timer.start(val * 1000)

    def on_live_tick(self):
        if not hasattr(self, "last_frame"):
            self.sb.showMessage("Live: no frame yet", 2000)
            return
        # Avoid overlapping runs
        if hasattr(self, "ai") and self.ai.isRunning():
            return
        self.analyze()

    # NEW: MULTI-FRAME ANALYSIS
    def multi_frame_analyze(self):
        n = self.multi_n.value()
        if len(self.frame_buffer) < 2:
            self.sb.showMessage("Not enough frames for multi-frame analysis", 5000)
            return

        frames = self.frame_buffer[-n:]
        url = self.cfg.get("url", "http://localhost:11434")
        model = self.cfg.get("model", "llama3.2-vision")
        extra = self.prompt.text().strip()

        self.ai_out.append(f"\n--- Multi-frame analysis (last {len(frames)} frames)... ---\n")

        self.ai = AIThread(
            url=url,
            model=model,
            frame=None,
            ocr=self.cfg.get("ocr", True),
            extra_prompt=extra,
            multi_frames=frames
        )
        self.ai.done.connect(self.on_ai_done)
        self.ai.error.connect(self.on_ai_error)
        self.ai.log.connect(self.on_ai_log)
        self.ai.ocr_debug.connect(self.on_ocr_debug)
        self.ai.start()

    def on_ai_done(self, txt, data):
        self.ai_out.append(txt + "\n")

        cmds = data.get("commands", [])
        if isinstance(cmds, list):
            for c in cmds:
                self.cmd_list.addItem(c)
                # NEW: append to command history with timestamp + source
                ts_now = dt.now().strftime("%Y-%m-%d %H:%M:%S")
                src = "multi-frame" if data.get("fallback_used") or "frames" in data.get("raw", "") else "single-frame"
                entry = f"[{ts_now}] ({src}) {c}"
                self.hist_list.addItem(entry)
                self.command_history.append({
                    "command": c,
                    "timestamp": ts_now,
                    "source": src,
                })

        findings = data.get("findings", "")
        if findings:
            self.rpt.append(f"\n[AI Findings]\n{findings}\n")

    def on_ai_error(self, msg):
        self.ai_out.append(f"\n[ERROR] {msg}\n")
        self.sb.showMessage(msg, 5000)

    def on_ai_log(self, msg):
        self.log_box.append(msg)

    def on_ocr_debug(self, text):
        self.ocr_box.clear()
        self.ocr_box.append(text)

    # SUMMARY
    def gen_summary(self):
        if not hasattr(self, "last_frame"):
            self.sb.showMessage("No frame yet", 5000)
            return

        url = self.cfg.get("url", "http://localhost:11434")
        model = self.cfg.get("model", "llama3.2-vision")

        self.ai_out.append("\n--- Generating summary... ---\n")

        self.ai = AIThread(
            url=url,
            model=model,
            frame=self.last_frame,
            ocr=self.cfg.get("ocr", True),
            extra_prompt="Provide a high-level summary of what is happening on screen."
        )
        self.ai.done.connect(self.on_ai_done)
        self.ai.error.connect(self.on_ai_error)
        self.ai.log.connect(self.on_ai_log)
        self.ai.ocr_debug.connect(self.on_ocr_debug)
        self.ai.start()

    # REPORT
    def save_report(self):
        try:
            ts = dt.now().strftime("%Y-%m-%d_%H-%M-%S")
            path = RPT_DIR / f"report_{ts}.txt"
            path.write_text(self.rpt.toPlainText(), encoding="utf-8")
            self.sb.showMessage(f"Saved: {path}", 5000)
        except Exception as e:
            log_error(f"Report save error: {e}")
            self.sb.showMessage("Failed to save report", 5000)

    # DRIVE
    def upload_drive(self):
        if not self.cfg.get("drive", False):
            self.sb.showMessage("Drive upload disabled in settings", 5000)
            return

        if not DRIVE:
            self.sb.showMessage("Google Drive libraries not installed", 5000)
            return

        try:
            ts = dt.now().strftime("%Y-%m-%d_%H-%M-%S")
            path = RPT_DIR / f"report_{ts}.txt"
            path.write_text(self.rpt.toPlainText(), encoding="utf-8")
        except Exception as e:
            log_error(f"Drive save error: {e}")
            self.sb.showMessage("Failed to save report", 5000)
            return

        if not self.drive.authenticated:
            creds_path, _ = QFileDialog.getOpenFileName(
                self, "Select Google credentials.json", "", "JSON Files (*.json)"
            )
            if not creds_path:
                self.sb.showMessage("Drive auth canceled", 5000)
                return

            ok, msg = self.drive.authenticate(creds_path)
            if not ok:
                self.sb.showMessage(f"Auth failed: {msg}", 5000)
                return

        ok, msg = self.drive.upload_file(path)
        if ok:
            self.sb.showMessage(f"Uploaded: {msg}", 5000)
        else:
            self.sb.showMessage(f"Upload failed: {msg}", 5000)

    # SETTINGS
    def open_settings(self):
        dlg = CyberSettings(self, self.cfg)
        if dlg.exec():
            self.cfg = dlg.get()
            self.save_cfg()
            self.sb.showMessage("Settings saved", 3000)

    # RECORDING
    def start_recording(self):
        if not hasattr(self, "last_frame"):
            self.sb.showMessage("No frame yet", 5000)
            return

        ts = dt.now().strftime("%Y-%m-%d_%H-%M-%S")
        path = H / f"recording_{ts}.mp4"

        h, w, _ = self.last_frame.shape
        fps = self.cfg.get("fps", 30)

        if self.rec.start(path, fps, (w, h)):
            self.sb.showMessage(f"Recording started: {path}", 5000)
        else:
            self.sb.showMessage("Failed to start recording", 5000)

    def stop_recording(self):
        path = self.rec.stop()
        if path:
            self.sb.showMessage(f"Recording saved: {path}", 5000)
        else:
            self.sb.showMessage("Recording stopped", 5000)

    # CLOSE
    def closeEvent(self, e):
        try:
            if self.st.running:
                self.st.stop()
                self.st.wait(500)
        except Exception as ex:
            log_error(f"Close event error: {ex}")

        try:
            if self.rec.rec:
                self.rec.stop()
        except Exception as ex:
            log_error(f"Recorder stop error: {ex}")

        try:
            if self.live_running:
                self.live_timer.stop()
        except Exception as ex:
            log_error(f"Live timer stop error: {ex}")

        e.accept()

    # MENU
    def create_menu(self):
        m = self.menuBar()

        f = m.addMenu("File")
        act_save = f.addAction("Save Report")
        act_save.triggered.connect(self.save_report)
        act_drive = f.addAction("Upload to Drive")
        act_drive.triggered.connect(self.upload_drive)
        f.addSeparator()
        act_exit = f.addAction("Exit")
        act_exit.triggered.connect(self.close)

        s = m.addMenu("Settings")
        act_set = s.addAction("Preferences")
        act_set.triggered.connect(self.open_settings)

        r = m.addMenu("Recording")
        act_rec_start = r.addAction("Start Recording")
        act_rec_start.triggered.connect(self.start_recording)
        act_rec_stop = r.addAction("Stop Recording")
        act_rec_stop.triggered.connect(self.stop_recording)

    # UTILITY
    def show_message(self, msg, timeout=5000):
        self.sb.showMessage(msg, timeout)


# ============================================================
# ENTRY POINT
# ============================================================

def main():
    try:
        app = QApplication(sys.argv)
        win = MainWindow()
        win.show()
        sys.exit(app.exec())
    except Exception as e:
        log_error(f"Fatal startup error: {e}")
        print("A fatal error occurred. Check ~/.cybersec/error.log for details.")


if __name__ == "__main__":
    main()
