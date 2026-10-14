"""
Pure-Python Context-Triggered Piecewise Hashing (CTPH / SSDEEP-compatible)
and Automated Campaign Clustering for EntropyStrip.
Zero external C-library or compiler dependencies.
"""

from typing import List, Dict, Any, Optional, Tuple

B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ROLLING_WINDOW = 7


class RollingHash:
    """7-byte cyclic rolling hash state."""
    __slots__ = ("h1", "h2", "h3", "window", "n")

    def __init__(self) -> None:
        self.h1 = 0
        self.h2 = 0
        self.h3 = 0
        self.window = [0] * ROLLING_WINDOW
        self.n = 0

    def update(self, b: int) -> int:
        self.h2 -= self.h1
        self.h2 += ROLLING_WINDOW * b
        self.h1 += b
        self.h1 -= self.window[self.n % ROLLING_WINDOW]
        self.window[self.n % ROLLING_WINDOW] = b
        self.n += 1
        self.h3 = ((self.h3 << 5) & 0xFFFFFFFF) ^ b
        return (self.h1 + self.h2 + self.h3) & 0xFFFFFFFF


def fnv_hash(data: bytes) -> int:
    """FNV-1a 32-bit hash."""
    h = 0x811C9DC5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def compute_piecewise_hash(data: bytes, block_size: int) -> Tuple[str, str]:
    """Generates two piecewise hash strings for block_size and block_size * 2."""
    rh = RollingHash()
    h1_chars: List[str] = []
    h2_chars: List[str] = []

    bs1 = block_size
    bs2 = block_size * 2

    # Running 32-bit FNV-1a accumulators for independent piecewise chunking
    fnv1 = 0x811C9DC5
    fnv2 = 0x811C9DC5

    for b in data:
        fnv1 = ((fnv1 ^ b) * 0x01000193) & 0xFFFFFFFF
        fnv2 = ((fnv2 ^ b) * 0x01000193) & 0xFFFFFFFF
        h_val = rh.update(b)

        if h_val % bs1 == (bs1 - 1):
            if len(h1_chars) < 64:
                h1_chars.append(B64_CHARS[fnv1 % 64])
                fnv1 = 0x811C9DC5

        if h_val % bs2 == (bs2 - 1):
            if len(h2_chars) < 32:
                h2_chars.append(B64_CHARS[fnv2 % 64])
                fnv2 = 0x811C9DC5

    if len(h1_chars) < 64:
        h1_chars.append(B64_CHARS[fnv1 % 64])
    if len(h2_chars) < 32:
        h2_chars.append(B64_CHARS[fnv2 % 64])

    return "".join(h1_chars), "".join(h2_chars)


def compute_fuzzy_hash(data: bytes) -> str:
    """
    Computes an SSDEEP-compatible Context-Triggered Piecewise Hash (CTPH).
    Returns string in format: '<block_size>:<hash1>:<hash2>'.
    Bounded to 512KB sample size for high-speed pure-Python triage.
    """
    if not data:
        return "3::"

    sample = data[:512 * 1024]

    # Select optimal block size
    block_size = 3
    while block_size * 64 < len(sample):
        block_size *= 2

    h1, h2 = compute_piecewise_hash(sample, block_size)
    if len(h1) < 16 and block_size > 3:
        # Try half block size once if string is too short
        h1_half, h2_half = compute_piecewise_hash(sample, block_size // 2)
        if len(h1_half) > len(h1):
            return f"{block_size // 2}:{h1_half}:{h2_half}"

    return f"{block_size}:{h1}:{h2}"


def _levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if s1 == s2:
        return 0
    if not s1:
        return len(s2)
    if not s2:
        return len(s1)

    v0 = list(range(len(s2) + 1))
    v1 = [0] * (len(s2) + 1)

    for i in range(len(s1)):
        v1[0] = i + 1
        for j in range(len(s2)):
            cost = 0 if s1[i] == s2[j] else 1
            v1[j + 1] = min(v1[j] + 1, v0[j + 1] + 1, v0[j] + cost)
        v0[:] = v1

    return v0[len(s2)]


def compare_fuzzy_hashes(h1: str, h2: str) -> int:
    """
    Compares two CTPH / SSDEEP fuzzy hashes and returns a similarity score from 0 to 100.
    """
    if not h1 or not h2 or ":" not in h1 or ":" not in h2:
        return 0
    if h1 == h2:
        return 100

    try:
        parts1 = h1.split(":", 2)
        parts2 = h2.split(":", 2)
        if len(parts1) < 3 or len(parts2) < 3:
            return 0

        bs1 = int(parts1[0])
        bs2 = int(parts2[0])
        s1_1, s1_2 = parts1[1], parts1[2]
        s2_1, s2_2 = parts2[1], parts2[2]

        score = 0
        if bs1 == bs2:
            # Direct comparison
            score1 = _score_strings(s1_1, s2_1)
            score2 = _score_strings(s1_2, s2_2)
            score = max(score1, score2)
        elif bs1 == bs2 * 2:
            score = _score_strings(s1_1, s2_2)
        elif bs2 == bs1 * 2:
            score = _score_strings(s1_2, s2_1)

        return score
    except Exception:
        return 0


def _score_strings(s1: str, s2: str) -> int:
    """Calculates normalized match score for two piecewise strings."""
    if not s1 or not s2:
        return 0
    if s1 == s2:
        return 100

    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 0

    dist = _levenshtein_distance(s1, s2)
    match_ratio = 1.0 - (dist / max_len)
    return max(0, min(100, int(match_ratio * 100)))


def cluster_samples(
    samples: List[Dict[str, Any]],
    similarity_threshold: int = 70,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Groups samples into campaign similarity clusters based on fuzzy hashing (SSDEEP).
    
    Returns:
        Mapping of cluster_name (e.g. 'Cluster-1') -> list of matching samples.
    """
    valid_samples = [s for s in samples if s.get("fuzzy_hash")]
    n = len(valid_samples)
    if n <= 1:
        return {}

    # Build adjacency matrix
    adj: Dict[int, List[int]] = {i: [] for i in range(n)}
    for i in range(n):
        for j in range(i + 1, n):
            h1 = valid_samples[i]["fuzzy_hash"]
            h2 = valid_samples[j]["fuzzy_hash"]
            sim = compare_fuzzy_hashes(h1, h2)
            if sim >= similarity_threshold:
                adj[i].append(j)
                adj[j].append(i)

    # Connected components
    visited = set()
    clusters: Dict[str, List[Dict[str, Any]]] = {}
    cluster_idx = 1

    for i in range(n):
        if i not in visited:
            component = []
            queue = [i]
            visited.add(i)
            while queue:
                curr = queue.pop(0)
                component.append(valid_samples[curr])
                for neighbor in adj[curr]:
                    if neighbor not in visited:
                        visited.add(neighbor)
                        queue.append(neighbor)

            if len(component) >= 2:
                c_name = f"Campaign-Cluster-{cluster_idx}"
                clusters[c_name] = component
                for s in component:
                    s["cluster_id"] = c_name
                cluster_idx += 1

    return clusters
