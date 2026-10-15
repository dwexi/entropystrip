"""
Shannon entropy and dual-scale sliding-window radar.
"""

import math
from typing import List, Tuple, Dict, Any, Optional

# Sampling limit for massive sections/overlays to keep triage instantaneous
LARGE_BUFFER_SAMPLE_LIMIT = 1_000_000
SAMPLE_CHUNK_SIZE = 200_000
SAMPLE_NUM_CHUNKS = 5


def sample_large_buffer(data: bytes) -> bytes:
    """
    Strided multi-chunk sampling across multi-megabyte buffers.
    Extracts 5 equidistant 200KB chunks (head, interior strides, and tail) to prevent latency
    degradation while eliminating central payload evasion blind spots (D2-06).
    """
    total_len = len(data)
    if total_len > LARGE_BUFFER_SAMPLE_LIMIT:
        stride = (total_len - SAMPLE_CHUNK_SIZE) // (SAMPLE_NUM_CHUNKS - 1)
        chunks = []
        for i in range(SAMPLE_NUM_CHUNKS):
            offset = min(total_len - SAMPLE_CHUNK_SIZE, i * stride)
            chunks.append(data[offset : offset + SAMPLE_CHUNK_SIZE])
        return b"".join(chunks)
    return data


def calculate_entropy(data: bytes) -> float:
    """
    Calculates standard Shannon entropy H(X) across byte distribution:
        H(X) = -sum(P(x) * log2(P(x))) for x in 0..255
    Returns a score between 0.0 (uniform single byte) and 8.0 (pure randomness/encryption).
    """
    if not data:
        return 0.0

    buf = sample_large_buffer(data)
    length = len(buf)
    byte_counts = [0] * 256
    for b in buf:
        byte_counts[b] += 1

    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy


def scan_sliding_window_entropy(
    data: bytes,
    window_size: int = 1024,
    step_size: Optional[int] = None,
    threshold: float = 7.4,
) -> Tuple[float, List[Dict[str, Any]]]:
    """
    Performs sub-section sliding-window inspection.
    
    Averages over an entire PE section mask localized encrypted or packed payloads.
    Scanning in 1024-byte and 256-byte windows with adaptive stepping catches compact
    stagers regardless of total section size.
    """
    if not data:
        return 0.0, []

    if len(data) < 256:
        sub_ent = calculate_entropy(data)
        spans = []
        if sub_ent >= threshold:
            spans.append({
                "start": 0,
                "end": len(data),
                "max_ent": sub_ent,
                "scale": len(data),
            })
        return sub_ent, spans

    # Scale step size on large buffers to maintain sub-second triage speeds
    if step_size is None:
        if len(data) > 500_000:
            step_size = min(1024, max(512, len(data) // 150))
        else:
            step_size = 512

    effective_window = min(window_size, len(data))
    max_ent = 0.0
    anomalous_spans = []
    current_span = None

    offsets = list(range(0, len(data) - effective_window + 1, step_size))
    tail_offset = len(data) - effective_window
    if tail_offset > 0 and (not offsets or offsets[-1] != tail_offset):
        offsets.append(tail_offset)

    for offset in offsets:
        chunk = data[offset : offset + effective_window]
        ent = calculate_entropy(chunk)
        if ent > max_ent:
            max_ent = ent

        if ent >= threshold:
            if current_span is None:
                current_span = {
                    "start": offset,
                    "end": offset + effective_window,
                    "max_ent": ent,
                    "scale": effective_window,
                }
            else:
                current_span["end"] = max(current_span["end"], offset + effective_window)
                if ent > current_span["max_ent"]:
                    current_span["max_ent"] = ent
        else:
            if current_span is not None:
                anomalous_spans.append(current_span)
                current_span = None

    if current_span is not None:
        anomalous_spans.append(current_span)

    # 256-byte secondary pass for compact stagers (e.g. 300-500 byte shellcode stagers)
    if not anomalous_spans and len(data) >= 256:
        sub_win = 256
        sub_step = 64 if len(data) <= 500_000 else 256
        scan_limit = min(len(data), 2_000_000)
        sub_offsets = list(range(0, scan_limit - sub_win + 1, sub_step))
        sub_tail = scan_limit - sub_win
        if sub_tail > 0 and (not sub_offsets or sub_offsets[-1] != sub_tail):
            sub_offsets.append(sub_tail)

        for offset in sub_offsets:
            chunk = data[offset : offset + sub_win]
            sub_ent = calculate_entropy(chunk)
            if sub_ent > max_ent:
                max_ent = sub_ent
            if sub_ent >= 7.15:
                anomalous_spans.append(
                    {
                        "start": offset,
                        "end": offset + sub_win,
                        "max_ent": sub_ent,
                        "scale": 256,
                    }
                )
                break

    return max_ent, anomalous_spans


def get_entropy_heatmap_string(data: bytes, width: int = 30) -> str:
    """
    Generates a 30-character colored block representation of section entropy distribution.
    """
    if not data:
        return "[dim]No Data (Unmapped)[/dim]"

    chunk_size = max(1, len(data) // width)
    heatmap = ""
    for i in range(width):
        start = i * chunk_size
        end = len(data) if i == width - 1 else start + chunk_size
        chunk = data[start : start + 50_000] if (end - start) > 50_000 else data[start:end]
        if not chunk:
            continue
        ent = calculate_entropy(chunk)
        if ent > 7.4:
            color = "red"
        elif ent > 6.6:
            color = "yellow"
        elif ent > 5.0:
            color = "green"
        elif ent > 1.0:
            color = "blue"
        else:
            color = "bright_black"
        heatmap += f"[{color}]█[/{color}]"
    return heatmap
