"""
Anti-evasion radar: byte distribution, Chi-Square (χ²), and modal dilution analysis.
"""

import math
from typing import Tuple, List, Set
from .entropy import calculate_entropy, sample_large_buffer


def calculate_dilution_metrics(data: bytes) -> Tuple[float, float, bool, str]:
    """
    Detects single-mode and multimodal entropy dilution attacks.
    
    Attackers dilute dense ciphertext by interleaving null bytes, NOP sleds (0x90),
    or delimiter characters (including multiple alternating padding bytes),
    dragging global section entropy below detection thresholds (5.0-6.0).
    
    This function extracts single and composite modal padding bytes and tests
    the residual entropy of the non-padded remainder.
    """
    if not data or len(data) < 512:
        return 0.0, 0.0, False, "none"

    buf = sample_large_buffer(data)
    n = len(buf)
    counts = [0] * 256
    for b in buf:
        counts[b] += 1

    # Identify all modal outlier candidates where frequency >= 12%
    modal_candidates = [b for b in range(256) if (counts[b] / n) >= 0.12]
    modal_candidates.sort(key=lambda b: counts[b], reverse=True)

    if not modal_candidates:
        max_c = max(counts)
        return 0.0, max_c / n, False, "none"

    top_mode = modal_candidates[0]
    top_ratio = counts[top_mode] / n

    # 1. Single modal byte check (dominant padding byte >= 28%)
    if top_ratio >= 0.28:
        non_pad_single = bytes([b for b in buf if b != top_mode])
        if len(non_pad_single) >= 256:
            ent_single = calculate_entropy(non_pad_single)
            if ent_single > 7.35:
                pad_name = "null-byte" if top_mode == 0 else f"repeated-byte (0x{top_mode:02X})"
                return ent_single, top_ratio, True, pad_name

    # 2. Multimodal padding check (2 to 4 alternating padding bytes dominating >= 30%)
    if len(modal_candidates) >= 2:
        modal_set = set(modal_candidates[:4])
        total_modal_count = sum(counts[b] for b in modal_set)
        total_pad_ratio = total_modal_count / n

        if total_pad_ratio >= 0.30:
            non_pad_multi = bytes([b for b in buf if b not in modal_set])
            if len(non_pad_multi) >= 256:
                ent_multi = calculate_entropy(non_pad_multi)
                if ent_multi > 7.30:
                    hex_modes = ", ".join([f"0x{b:02X}" for b in modal_candidates[:4]])
                    pad_name = f"multimodal repeated-byte ({hex_modes})"
                    return ent_multi, total_pad_ratio, True, pad_name

    return 0.0, top_ratio, False, "none"


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

    # Detect dominant mode(s) with frequency >= 12%
    modal_candidates = [b for b in range(256) if (counts[b] / n) >= 0.12]
    modal_candidates.sort(key=lambda b: counts[b], reverse=True)
    if not modal_candidates:
        return chi2, 0.0, False

    # Take top mode, or top composite modes if multimodal
    if len(modal_candidates) >= 2 and (sum(counts[b] for b in modal_candidates[:4]) / n) >= 0.25:
        mode_set = set(modal_candidates[:4])
    else:
        mode_set = {modal_candidates[0]}

    pad_ratio = sum(counts[b] for b in mode_set) / n
    non_mode_counts = [counts[b] for b in range(256) if b not in mode_set]
    nz_total = sum(non_mode_counts)
    is_diluted_uniform = False
    nz_chi2 = 0.0

    k = len(mode_set)
    dof = 256 - k - 1
    # Check minimum sample size to avoid Cochran's rule violation (expected count >= 5 per bin)
    min_sample = (256 - k) * 5 # ~1270 bytes
    if pad_ratio >= 0.15 and nz_total >= min_sample:
        nz_expected = nz_total / float(256 - k)
        nz_chi2 = sum(((c - nz_expected) ** 2) / nz_expected for c in non_mode_counts)
        # Expected value is dof, std dev is sqrt(2 * dof)
        mu = float(dof)
        sigma = math.sqrt(2.0 * dof)
        lower_bound = max(100.0, mu - 4.0 * sigma)
        upper_bound = mu + 4.0 * sigma
        if lower_bound <= nz_chi2 <= upper_bound:
            is_diluted_uniform = True
    elif pad_ratio >= 0.15 and nz_total >= 512 and k == 1:
        # Fallback for moderate single-mode buffers
        nz_expected = nz_total / 255.0
        nz_chi2 = sum(((c - nz_expected) ** 2) / nz_expected for c in non_mode_counts)
        if 160.0 <= nz_chi2 <= 420.0:
            is_diluted_uniform = True

    return chi2, nz_chi2, is_diluted_uniform
