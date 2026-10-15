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

    h1_has_residual = False
    h2_has_residual = False

    for b in data:
        fnv1 = ((fnv1 ^ b) * 0x01000193) & 0xFFFFFFFF
        fnv2 = ((fnv2 ^ b) * 0x01000193) & 0xFFFFFFFF
        h_val = rh.update(b)
        h1_has_residual = True
        h2_has_residual = True

        if h_val % bs1 == (bs1 - 1):
            if len(h1_chars) < 64:
                h1_chars.append(B64_CHARS[fnv1 % 64])
                fnv1 = 0x811C9DC5
                h1_has_residual = False

        if h_val % bs2 == (bs2 - 1):
            if len(h2_chars) < 64:
                h2_chars.append(B64_CHARS[fnv2 % 64])
                fnv2 = 0x811C9DC5
                h2_has_residual = False

    if h1_has_residual and len(h1_chars) < 64:
        h1_chars.append(B64_CHARS[fnv1 % 64])
    if h2_has_residual and len(h2_chars) < 64:
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
    # Enforce minimum string length to prevent degenerate false-positive collisions (D2-01)
    if min(len(s1), len(s2)) < 4:
        return 100 if (s1 == s2 and len(s1) >= 4) else 0

    # Require a minimum common contiguous substring of at least 4 characters
    has_common = False
    for i in range(len(s1) - 3):
        if s1[i : i + 4] in s2:
            has_common = True
            break
    if not has_common:
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
    Uses complete-linkage (clique) clustering so all samples in a cluster share
    pairwise similarity >= similarity_threshold, preventing transitive chaining collapse.
    
    Returns:
        Mapping of cluster_name (e.g. 'Campaign-Cluster-1') -> list of matching samples.
    """
    valid_samples = [s for s in samples if s.get("fuzzy_hash")]
    n = len(valid_samples)
    if n <= 1:
        return {}

    # Build pairwise similarity matrix
    sim_matrix = [[0] * n for _ in range(n)]
    for i in range(n):
        sim_matrix[i][i] = 100
        for j in range(i + 1, n):
            h1 = valid_samples[i]["fuzzy_hash"]
            h2 = valid_samples[j]["fuzzy_hash"]
            sim = compare_fuzzy_hashes(h1, h2)
            sim_matrix[i][j] = sim
            sim_matrix[j][i] = sim

    # Complete-linkage clustering
    clusters: Dict[str, List[Dict[str, Any]]] = {}
    cluster_idx = 1
    unassigned = set(range(n))

    # Order nodes by candidate neighbors meeting threshold
    degrees = [
        sum(1 for j in range(n) if i != j and sim_matrix[i][j] >= similarity_threshold)
        for i in range(n)
    ]
    sorted_nodes = sorted(range(n), key=lambda x: degrees[x], reverse=True)

    for i in sorted_nodes:
        if i not in unassigned:
            continue

        candidates = [j for j in unassigned if j != i and sim_matrix[i][j] >= similarity_threshold]
        if not candidates:
            continue

        clique = [i]
        for cand in candidates:
            if all(sim_matrix[cand][member] >= similarity_threshold for member in clique):
                clique.append(cand)

        if len(clique) >= 2:
            c_name = f"Campaign-Cluster-{cluster_idx}"
            cluster_members = [valid_samples[idx] for idx in clique]
            clusters[c_name] = cluster_members
            for s in cluster_members:
                s["cluster_id"] = c_name
            cluster_idx += 1
            for idx in clique:
                unassigned.remove(idx)

    return clusters
