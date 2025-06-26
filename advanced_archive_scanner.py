import os
import zipfile
import rarfile
import py7zr
import tarfile
from pycdlib import PyCdlib
import shutil
import tempfile
import magic
import traceback

from utils.logger import log_event
from utils.popups import show_popup
from ai.mistral_analysis import analyze_text

SUPPORTED_EXTENSIONS = ('.zip', '.rar', '.7z', '.iso', '.tar', '.gz', '.xz', '.bz2', '.cab', '.img', '.vhd')

def extract_iso_files(iso_path, extract_to):
    from pycdlib.pycdlibexception import PyCdlibException
    iso = PyCdlib()
    try:
        iso.open(iso_path)
        if not os.path.exists(extract_to):
            os.makedirs(extract_to, exist_ok=True)

        # List all files in ISO using get_record()
        import io
        for child in iso.list_children(iso_path='/'):
            try:
                filename = child.file_identifier().decode('utf-8').rstrip(';1')
                iso_fp_path = '/' + child.file_identifier().decode('utf-8')

                out_path = os.path.join(extract_to, filename)

                with open(out_path, 'wb') as out_file:
                    iso.get_file_from_iso_fp(out_file, iso_path=iso_fp_path)
            except PyCdlibException as e:
                log_event("ISO_CHILD_ERROR", f"Failed on child: {e}")
                continue
            except Exception as e:
                log_event("ISO_EXTRACT_FILE_ERROR", f"{iso_path}: {e}")
                continue
    except Exception as e:
        log_event("ISO_EXTRACT_ERROR", f"{iso_path}: {e}")
    finally:
        iso.close()


def is_high_entropy(file_path, threshold=7.5):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if not data:
            return False
        from math import log2
        entropy = -sum((data.count(byte) / len(data)) * log2(data.count(byte) / len(data)) for byte in set(data))
        return entropy > threshold
    except Exception:
        return False

def extract_archive(file_path, extract_dir):
    try:
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as zf:
                zf.extractall(extract_dir)
                return True, zf.namelist(), zf.testzip() is not None
        elif rarfile.is_rarfile(file_path):
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(extract_dir)
                return True, rf.namelist(), rf.needs_password()
        elif file_path.endswith('.7z'):
            with py7zr.SevenZipFile(file_path, mode='r') as zf:
                zf.extractall(path=extract_dir)
                return True, zf.getnames(), zf.needs_password()
        elif tarfile.is_tarfile(file_path):
            with tarfile.open(file_path) as tf:
                tf.extractall(path=extract_dir)
                return True, tf.getnames(), False
        elif file_path.endswith('.iso'):
            extract_iso_files(file_path, extract_dir)
            return True, os.listdir(extract_dir), False
    except Exception as e:
        log_event("ARCHIVE_EXTRACT_ERROR", f"{file_path}: {e}")
        return False, [], False
    return False, [], False

def scan_file(file_path, metadata, ai_reason_list):
    try:
        file_type = magic.from_file(file_path, mime=True)
        metadata['file_type'] = file_type

        filename = os.path.basename(file_path).lower()

        suspicious = []

        if filename.endswith(('.vbs', '.js', '.wsf', '.scr', '.ps1')):
            suspicious.append('Uncommon/obfuscated script')

        if filename.endswith(('.docm', '.xlsm', '.pptm')):
            suspicious.append('Macro-enabled Office file')

        if any(name in filename for name in ['mshta', 'rundll32', 'regsvr32', 'powershell', 'cmd']):
            suspicious.append('LOLBin')

        if is_high_entropy(file_path):
            suspicious.append('High entropy (possibly packed/encrypted)')

        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read(10000)
                if 'sleep' in content and any(t in content for t in ['30', '60', '300', '1000']):
                    suspicious.append('Time-delayed execution')
        except:
            pass

        metadata['suspicious_tags'] = suspicious

        prompt = f"Analyze the following file:\n\nName: {filename}\nTags: {', '.join(suspicious)}\nFileType: {file_type}\n"
        ai_result = analyze_text(prompt)

        if isinstance(ai_result, dict) and ai_result.get("DANGEROUS"):
            show_popup("Guardrail Archive Alert", f"{filename}\n\n{ai_result['reason']}")
            log_event("ARCHIVE_FILE_FLAGGED", f"{filename} | {ai_result}")
            ai_reason_list.append((filename, ai_result['reason']))
        else:
            log_event("ARCHIVE_FILE_SAFE", f"{filename} | {ai_result}")
    except Exception as e:
        log_event("FILE_SCAN_ERROR", f"{file_path}: {e}")

def scan_archive_recursive(archive_path):
    if not os.path.exists(archive_path) or not archive_path.lower().endswith(SUPPORTED_EXTENSIONS):
        return

    temp_dir = tempfile.mkdtemp()
    flagged_items = []

    try:
        success, extracted_files, password_protected = extract_archive(archive_path, temp_dir)
        if not success:
            log_event("ARCHIVE_EXTRACT_FAIL", archive_path)
            return

        if password_protected:
            log_event("ARCHIVE_PASSWORD", f"Password-protected archive: {archive_path}")
            prompt = f"Archive {os.path.basename(archive_path)} is password-protected. Flag for risk?"
            ai_result = analyze_text(prompt)
            if isinstance(ai_result, dict) and ai_result.get("DANGEROUS"):
                show_popup("Guardrail Alert", f"{archive_path}\n\n{ai_result['reason']}")
                flagged_items.append((archive_path, ai_result['reason']))

        for root, dirs, files in os.walk(temp_dir):
            for name in files:
                full_path = os.path.join(root, name)
                meta = {"original_archive": archive_path, "full_path": full_path}
                if name.lower().endswith(SUPPORTED_EXTENSIONS):
                    scan_archive_recursive(full_path)
                else:
                    scan_file(full_path, meta, flagged_items)
    except Exception as e:
        log_event("ARCHIVE_SCAN_ERROR", f"{archive_path}: {traceback.format_exc()}")
    finally:
        shutil.rmtree(temp_dir)

def scan_folder_for_archives(folder_path):
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.lower().endswith(SUPPORTED_EXTENSIONS):
                archive_path = os.path.join(root, file)
                log_event("ARCHIVE_FOUND", str(archive_path))
                scan_archive_recursive(archive_path)
