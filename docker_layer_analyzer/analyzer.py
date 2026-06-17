import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .parser import ImageInfo, LayerInfo, _parse_whiteout_name


CACHE_PATTERNS = [
    (r"/var/cache/apt/archives/.*\.deb$", "apt cache (.deb packages)"),
    (r"/var/lib/apt/lists/.*$", "apt lists"),
    (r"/var/cache/yum/.*$", "yum cache"),
    (r"/var/cache/dnf/.*$", "dnf cache"),
    (r"/root/.npm/_cacache/.*$", "npm cache"),
    (r"/home/[^/]+/.npm/_cacache/.*$", "npm cache (user)"),
    (r"/usr/local/lib/node_modules/npm/_cacache/.*$", "npm global cache"),
    (r"/root/.cache/pip/.*$", "pip cache"),
    (r"/home/[^/]+/.cache/pip/.*$", "pip cache (user)"),
    (r"/tmp/.*$", "temporary file (/tmp)"),
    (r"/var/tmp/.*$", "temporary file (/var/tmp)"),
    (r"/var/log/.*$", "log file (/var/log)"),
    (r"/root/.cache/.*$", "root cache directory"),
    (r"/home/[^/]+/.cache/.*$", "user cache directory"),
    (r"/run/.*\.pid$", "PID file"),
    (r"/var/lib/dpkg/info/.*\.list$", "dpkg info list"),
    (r"/usr/share/doc/.*$", "documentation files"),
    (r"/usr/share/man/.*$", "man pages"),
    (r"/usr/share/locale/.*$", "locale files"),
    (r"/__pycache__/.*$", "Python bytecode cache"),
    (r".*\.pyc$", "Python compiled file"),
    (r".*\.pyo$", "Python optimized file"),
    (r"/root/.rustup/.*$", "rustup toolchain"),
    (r"/root/.cargo/registry/.*$", "cargo registry cache"),
    (r"/go/pkg/mod/cache/.*$", "go module cache"),
    (r"/root/.gradle/caches/.*$", "gradle cache"),
    (r"/root/.m2/repository/.*$", "maven cache"),
]

MERGEABLE_COMMANDS = [
    ("apt-get update", "apt-get install"),
    ("apt-get update", "apt-get upgrade"),
    ("yum check-update", "yum install"),
    ("dnf check-update", "dnf install"),
    ("npm install", "npm cache clean"),
    ("pip install", "pip cache purge"),
    ("apk update", "apk add"),
]


@dataclass
class SizeDistribution:
    layer_id: str
    size: int
    percentage: float
    bar: str


@dataclass
class CacheFinding:
    path: str
    category: str
    size: int
    layer_index: int
    layer_id: str


@dataclass
class MergeSuggestion:
    layer_indices: List[int]
    reason: str
    potential_saving: int
    involved_files: List[Tuple[int, str, int]] = field(default_factory=list)


@dataclass
class SlimmingReport:
    cache_findings: List[CacheFinding] = field(default_factory=list)
    merge_suggestions: List[MergeSuggestion] = field(default_factory=list)
    duplicate_waste: int = 0
    total_cache_size: int = 0
    total_potential_saving: int = 0


def calculate_size_distribution(image: ImageInfo) -> List[SizeDistribution]:
    if image.total_size == 0:
        return []

    distributions = []
    for layer in image.layers:
        pct = (layer.size / image.total_size) * 100
        bar_len = int(pct / 2)
        bar = "█" * bar_len + "░" * (50 - bar_len)
        distributions.append(SizeDistribution(
            layer_id=layer.id,
            size=layer.size,
            percentage=pct,
            bar=bar,
        ))
    return distributions


def find_cache_files(image: ImageInfo) -> List[CacheFinding]:
    findings = []
    compiled = [(re.compile(p), desc) for p, desc in CACHE_PATTERNS]

    for i, layer in enumerate(image.layers):
        for f in layer.files:
            search_path = f.path if f.path.startswith("/") else f"/{f.path}"
            for pattern, category in compiled:
                if pattern.search(search_path):
                    findings.append(CacheFinding(
                        path=f.path,
                        category=category,
                        size=f.size,
                        layer_index=i,
                        layer_id=layer.id,
                    ))
                    break

    return findings


def _extract_run_commands(created_by: str) -> List[str]:
    commands = []
    for part in created_by.split("&&"):
        cmd = part.strip()
        if cmd.startswith("/bin/sh -c "):
            cmd = cmd[len("/bin/sh -c "):]
        elif cmd.startswith("/bin/sh -c"):
            cmd = cmd[len("/bin/sh -c"):]
        cmd = cmd.strip()
        if cmd:
            commands.append(cmd)
    return commands


def find_mergeable_layers(image: ImageInfo) -> List[MergeSuggestion]:
    suggestions = []
    n = len(image.layers)

    for i in range(n - 1):
        for j in range(i + 1, min(i + 5, n)):
            cmd_i = image.layers[i].created_by
            cmd_j = image.layers[j].created_by

            for pat_a, pat_b in MERGEABLE_COMMANDS:
                if pat_a in cmd_i and pat_b in cmd_j:
                    intermediate_delete = False
                    for k in range(i + 1, j):
                        if image.layers[k].deleted_files:
                            intermediate_delete = True
                            break

                    if not intermediate_delete:
                        saving = 0
                        involved = []
                        for k in range(i + 1, j + 1):
                            for f in image.layers[k].files:
                                if _parse_whiteout_name(f.path) is None:
                                    saving += f.size
                                    involved.append((k, f.path, f.size))

                        suggestions.append(MergeSuggestion(
                            layer_indices=list(range(i, j + 1)),
                            reason=f"'{pat_a}' and '{pat_b}' can be combined in a single RUN instruction",
                            potential_saving=saving,
                            involved_files=involved,
                        ))
                    break

    return suggestions


def generate_slimming_report(
    image: ImageInfo,
    duplicates: Dict[str, List[Tuple[int, int, str]]],
    duplicate_waste: int,
) -> SlimmingReport:
    cache_findings = find_cache_files(image)
    merge_suggestions = find_mergeable_layers(image)

    total_cache_size = sum(c.size for c in cache_findings)

    counted: Set[Tuple[int, str]] = set()
    total_potential = 0

    dedup_cache = 0
    for cf in cache_findings:
        key = (cf.layer_index, cf.path)
        if key not in counted:
            counted.add(key)
            dedup_cache += cf.size
    total_potential += dedup_cache

    dedup_duplicate = 0
    for path, occurrences in duplicates.items():
        for i in range(1, len(occurrences)):
            layer_idx, size, _ = occurrences[i]
            key = (layer_idx, path)
            if key not in counted:
                counted.add(key)
                dedup_duplicate += size
    total_potential += dedup_duplicate

    dedup_merge = 0
    for s in merge_suggestions:
        merge_saving = 0
        for layer_idx, file_path, file_size in s.involved_files:
            key = (layer_idx, file_path)
            if key not in counted:
                counted.add(key)
                merge_saving += file_size
        s.potential_saving = merge_saving
        total_potential += merge_saving
        dedup_merge += merge_saving

    return SlimmingReport(
        cache_findings=cache_findings,
        merge_suggestions=merge_suggestions,
        duplicate_waste=dedup_duplicate,
        total_cache_size=dedup_cache,
        total_potential_saving=total_potential,
    )
