# monitor/ransom_nlp.py

import os
import magic
import traceback
import pytesseract
from PIL import Image
from ai.mistral_analysis import analyze_text
from utils.logger import log_event
from utils.popups import show_popup

TEXT_PATTERNS = {
    "en": ["pay.*bitcoin", "decrypt.*key", "your files have been encrypted"],
    "ru": ["платеж.*биткоин", "файлы зашифрованы"],
    "cn": ["支付.*比特币", "文件已加密"],
}

IMAGE_EXTENSIONS = ('.png', '.jpg', '.jpeg', '.bmp', '.tiff')

def extract_text_from_file(filepath):
    try:
        mime = magic.from_file(filepath, mime=True)
        if mime.startswith("text") or filepath.endswith(".txt"):
            with open(filepath, 'r', errors='ignore') as f:
                return f.read()
        elif mime.startswith("image") or filepath.lower().endswith(IMAGE_EXTENSIONS):
            img = Image.open(filepath)
            return pytesseract.image_to_string(img)
        return ""
    except Exception as e:
        log_event("RANSOM_NOTE_EXTRACTION_ERROR", f"{filepath}: {e}")
        return ""

def scan_for_ransom_note(filepath):
    try:
        content = extract_text_from_file(filepath)
        if not content:
            return

        # Language-based pattern matching
        matched_lang = []
        for lang, patterns in TEXT_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, content, re.IGNORECASE):
                    matched_lang.append(lang)
                    break

        filename = os.path.basename(filepath).lower()
        prompt = f"""
A file named '{filename}' was detected with the following content:

---
{content[:1000]}
---

Determine whether this is a ransomware note in any language. Consider patterns like payment instructions, decryption keys, cryptocurrency addresses, and urgency messaging.

Multilingual analysis: English, Russian, Chinese.
Also flag if this appears to be image-based ransom text (OCR extracted).
"""

        result = analyze_text(prompt)

        if isinstance(result, dict) and result.get("DANGEROUS"):
            show_popup("🚨 Ransom Note Detected", result["reason"])
            log_event("RANSOM_NOTE_FLAGGED", f"{filepath} | {result}")
        else:
            log_event("RANSOM_NOTE_CLEAN", f"{filepath} | {result}")
    except Exception as e:
        log_event("RANSOM_NOTE_SCAN_ERROR", f"{filepath}: {traceback.format_exc()}")

def scan_directory_for_ransom_notes(folder_path):
    for root, _, files in os.walk(folder_path):
        for file in files:
            full_path = os.path.join(root, file)
            scan_for_ransom_note(full_path)
