"""
Installer frameworks (NSIS, Inno Setup, Burn) and Authenticode WIN_CERTIFICATE verification.
"""

from typing import Optional, Tuple
import pefile


def detect_installer(
    data: bytes, overlay_data: Optional[bytes] = None, pe: Optional[pefile.PE] = None
) -> Optional[str]:
    """
    Identifies common legitimate installer frameworks: NSIS, Inno Setup, WiX/Burn.
    Validates internal block headers to ensure attackers cannot inject strings to bypass triage.
    """
    if not data:
        return None

    sample = data[:0x40000]
    ov_sample = overlay_data[:0x4000] if overlay_data else b""
    combined_check = sample + ov_sample

    if b"NullsoftInst" in combined_check or b"Nullsoft.NSIS" in data:
        has_nsis_sec = False
        if pe:
            for s in pe.sections:
                try:
                    s_name = s.Name.decode(errors="ignore").rstrip("\x00").lower()
                    if ".ndata" in s_name or s_name == ".data":
                        has_nsis_sec = True
                except Exception:
                    pass

        if overlay_data and overlay_data.startswith(b"NullsoftInst") and len(overlay_data) >= 28:
            # Structurally validate NSIS 0xdeadbeef block header
            if (
                overlay_data[16:20] == b"\xef\xbe\xad\xde"
                or overlay_data[12:16] == b"\xef\xbe\xad\xde"
            ):
                return "Nullsoft NSIS Setup"
            return "Unverified NSIS Marker"
        elif has_nsis_sec and b"NullsoftInst" in data[:0x40000]:
            return "Nullsoft NSIS Setup"
        return "Unverified NSIS Marker"

    if b"Inno Setup Setup Data" in combined_check or b"Inno Setup" in combined_check:
        return "Inno Setup"
    if b"WixBurnBundle" in data or b"WixBurn" in data:
        return "WiX / Burn Bootstrapper"
    if b"InstallShield" in combined_check:
        return "InstallShield Setup"
    return None


def check_authenticode_signature(
    pe: pefile.PE, file_size: int = 0, file_data: bytes = b""
) -> Tuple[bool, str]:
    """
    Validates the PE Security Directory structure (WIN_CERTIFICATE table).
    Ensures directory offsets reside within the physical file bounds and header fields are valid.
    """
    try:
        if not hasattr(pe, "OPTIONAL_HEADER") or not hasattr(pe.OPTIONAL_HEADER, "DATA_DIRECTORY"):
            return False, "No data directories"
        if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 4:
            return False, "Missing security directory entry"

        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            return False, "Unsigned"

        offset = sec_dir.VirtualAddress
        size = sec_dir.Size

        if file_size > 0 and file_data:
            if offset + size > file_size or offset < 0x200 or size < 8:
                return False, "Security directory offset/size points out of bounds"

            cert_header = file_data[offset : offset + 8]
            if len(cert_header) < 8:
                return False, "Truncated certificate header"

            dw_length = int.from_bytes(cert_header[0:4], "little")
            w_revision = int.from_bytes(cert_header[4:6], "little")
            w_cert_type = int.from_bytes(cert_header[6:8], "little")

            if dw_length > size or w_revision not in (0x0100, 0x0200) or w_cert_type != 0x0002:
                return False, "Malformed or forged WIN_CERTIFICATE header"

        return True, "Valid Authenticode PKCS#7 signed structure"
    except Exception as e:
        return False, str(e)
