#!/usr/bin/env python3
"""
What kind of file went to removable media, in terms an exec reads: documents,
spreadsheets & data, email, medical images, ... Used by the falcon_usb
collector (stored per row) and by the exec report / action pack (labels,
colours, which categories count as business data).

The sensor's own file-type label (writtenFileType from Falcon's
dc_filewritten_events.csv lookup) can't tell an Outlook .msg from a Word .doc
(both OLE) or a .pst from anything else (Generic), so the extension decides
first and the sensor label is the fallback for files without a known one.
"""
import re
from typing import List, Optional, Tuple

# (key, label, colour, business data?, what it covers)
CATEGORIES: List[Tuple[str, str, str, bool, str]] = [
    ("documents", "Documents", "#2563eb", True, "PDF, Word, PowerPoint, Visio, RTF, text"),
    ("data", "Spreadsheets & data", "#0891b2", True, "Excel, CSV, Access and other database files"),
    ("email", "Email", "#7c3aed", True, "Outlook messages and mailbox exports (.msg, .eml, .pst)"),
    ("clinical", "Medical images", "#db2777", True, "DICOM imaging (.dcm)"),
    ("archives", "Archives", "#d97706", True, "zip, 7z, rar and similar -- contents unknown, so counted as data"),
    ("images", "Images & media", "#f59e0b", False, "photos, screenshots, audio, video"),
    ("software", "Applications & scripts", "#64748b", False, "programs, installers, scripts, Java"),
    ("cad", "Design & CAD", "#0d9488", False, "AutoCAD, Inventor, SolidWorks"),
    ("system", "Disk images & system", "#475569", False, "virtual disks, ISOs, memory dumps, databases of the OS"),
    ("other", "Other", "#cbd5e1", False, "anything not recognised"),
]
LABEL = {k: label for k, label, *_ in CATEGORIES}
COLOR = {k: color for k, _, color, *_ in CATEGORIES}
BUSINESS = tuple(k for k, _, _, b, _ in CATEGORIES if b)
ORDER = [k for k, *_ in CATEGORIES]

_EXT = {
    "documents": "pdf doc docx docm dot dotx rtf txt odt odp ppt pptx pptm pps ppsx vsd vsdx pub xps pages key md",
    "data": "xls xlsx xlsm xlsb xlt xltx csv tsv ods mdb accdb db sqlite sqlite3 sav dta sas7bdat dbf",
    "email": "msg eml emlx pst ost mbox oft",
    "clinical": "dcm dicom",
    "archives": "zip 7z rar gz tgz bz2 tbz xz tar cab arj arc xar lz lzh z",
    "images": "jpg jpeg png gif bmp tif tiff heic heif webp svg raw cr2 nef mp4 mov avi wmv mkv m4v mp3 wav m4a wma aac flac",
    "software": "exe dll msi msix appx sys scr com bat cmd ps1 psm1 vbs vbe js jse wsf hta jar py sh app dmg pkg xpi crx apk",
    "cad": "dwg dxf idw ipt iam sld sldprt sldasm step stp stl",
    "system": "vmdk vdi vhd vhdx iso img dmp mdmp edb ese",
}
EXT_CATEGORY = {ext: cat for cat, exts in _EXT.items() for ext in exts.split()}

# Falcon's writtenFileType labels (dc_filewritten_events.csv), for files whose
# extension says nothing
TYPE_CATEGORY = {
    "pdf file": "documents", "rtf file": "documents", "ole file": "documents", "ooxml file": "documents",
    "ms docx file": "documents", "ms pptx file": "documents", "ms vsdx file": "documents",
    "ms xlsx file": "data",
    "zip file": "archives", "gzip file": "archives", "bzip2 file": "archives", "sevenzip file": "archives",
    "rar file": "archives", "tar file": "archives", "cab file": "archives", "arc file": "archives",
    "arj file": "archives", "xar file": "archives",
    "jpeg file": "images", "png file": "images", "gif file": "images", "bmp file": "images", "tiff file": "images",
    "pe file": "software", "macho file": "software", "jar file": "software",
    "dwg file": "cad", "dxf file": "cad", "idw file": "cad", "sld file": "cad",
    "vmdk file": "system", "vdi file": "system", "dmp file": "system", "ese file": "system",
}

# Office lock/autosave files, OS clutter: written on every save, never the point
_NOISE = re.compile(r"(^~\$|^~wrl\d*\.tmp$|\.tmp$|^thumbs\.db$|^desktop\.ini$|^\.ds_store$|^\._)", re.I)
# deleting from a drive writes recycle-bin stubs; Windows keeps its own index there
_NOISE_PATH = re.compile(r"[\\/](\$RECYCLE\.BIN|System Volume Information|\.Trashes|\.Spotlight-V100|\.fseventsd)[\\/]", re.I)


def is_noise(file_name: Optional[str], file_path: Optional[str] = None) -> bool:
    if file_path and _NOISE_PATH.search(file_path):
        return True
    return bool(file_name) and bool(_NOISE.search(file_name.strip()))


def extension(file_name: Optional[str]) -> str:
    name = (file_name or "").strip()
    return name.rsplit(".", 1)[1].lower() if "." in name.lstrip(".") else ""


def categorise(file_name: Optional[str], written_type: Optional[str] = None) -> str:
    cat = EXT_CATEGORY.get(extension(file_name))
    if cat:
        return cat
    return TYPE_CATEGORY.get((written_type or "").strip().lower(), "other")


_VOLUME = re.compile(r"^(\\Device\\HarddiskVolume\d+\\|[A-Za-z]:\\|/Volumes/[^/]+/)")


def folder(file_path: Optional[str], depth: int = 2) -> str:
    """Top of the folder tree on the removable drive, e.g.
    '\\Device\\HarddiskVolume7\\FFI\\FDPortable\\ProgramData\\...' -> 'FFI\\FDPortable',
    so a whole program copied onto a stick is one line, not hundreds."""
    p = _VOLUME.sub("", (file_path or "").strip())
    parts = [s for s in re.split(r"[\\/]+", p) if s]
    return "\\".join(parts[:depth]) if parts else "(top level)"


def sql_in(keys) -> str:
    return "(" + ", ".join(f"'{k}'" for k in keys) + ")"
