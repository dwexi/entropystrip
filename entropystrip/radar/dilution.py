"""
Anti-evasion radar: byte distribution, Chi-Square (χ²), and modal dilution analysis.
"""

from typing import Tuple
from .entropy import calculate_entropy, sample_large_buffer


def calculate_dilution_metrics(data: bytes) -> Tuple[float, float, bool, str]:
    """
    Detects entropy dilution attacks.
    
    Attackers dilute dense ciphertext by interleaving null bytes, NOP sleds (0x90),
    or delimiter characters, dragging the global section entropy below detection thresholds (5.0-6.0).
    
    This function extracts the modal byte and tests the entropy of the non-padded remainder.
    """
    if not data or len(data) < 1024:
        return 0.0, 0.0, False, "none"

    buf = sample_large_buffer(data)
    counts = [0] * 256
    for b in buf:
        counts[b] += 1

    max_count = max(counts)
    mode_byte = counts.index(max_count)
    pad_ratio = max_count / len(buf)

    # If a single repeating padding character dominates >= 30% of the buffer
    if pad_ratio >= 0.30:
        non_pad_bytes = bytes([b for b in buf if b != mode_byte])
        if len(non_pad_bytes) >= 256:
            non_pad_ent = calculate_entropy(non_pad_bytes)
            # Flag if the non-padding bytes display cryptographic density
            if non_pad_ent > 7.38:
                pad_name = "null-byte" if mode_byte == 0 else f"repeated-byte (0x{mode_byte:02X})"
                return non_pad_ent, pad_ratio, True, pad_name

    return 0.0, pad_ratio, False, "none"


def calculate_chi_square(data: bytes) -> Tuple[float, float, bool]:
    """
    Computes Chi-Square goodness-of-fit against uniform byte distribution:
        chi2 = sum((observed - expected)^2 / expected)
        
    True compiled x86/x64 instructions follow distinct opcode frequency distributions,
    whereas artificially diluted ciphertext displays unnatural uniformity across non-mode bytes.
    """
    if not data or len(data) < 256:
        return 0.0, 0.0, False

    buf = sample_large_buffer(data)
    n = len(buf)
    counts = [0] * 256
    for b in buf:
        counts[b] += 1

    expected = n / 256.0
    chi2 = sum(((c - expected) ** 2) / expected for c in counts)

    max_count = max(counts)
    mode_byte = counts.index(max_count)
    pad_ratio = max_count / n
    non_mode_counts = [counts[b] for b in range(256) if b != mode_byte]
    nz_total = sum(non_mode_counts)
    is_diluted_uniform = False
    nz_chi2 = 0.0

    # Test non-mode byte uniformity for padded ciphertext
    if pad_ratio >= 0.15 and nz_total >= 512:
        nz_expected = nz_total / 255.0
        nz_chi2 = sum(((c - nz_expected) ** 2) / nz_expected for c in non_mode_counts)
        # Degrees of freedom = 254. Uniform randomness critical bounds fall between ~160 and 420.
        if 160.0 <= nz_chi2 <= 420.0:
            is_diluted_uniform = True

    return chi2, nz_chi2, is_diluted_uniform
