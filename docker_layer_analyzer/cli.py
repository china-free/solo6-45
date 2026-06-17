import argparse
import os
import sys
import tempfile
from collections import defaultdict
from typing import Dict, List, Tuple

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .parser import ImageInfo, LayerInfo, parse_image_tar, save_image_from_docker
from .differ import analyze_layer_diffs, calculate_duplicate_waste, find_duplicate_files
from .analyzer import (
    SlimmingReport,
    calculate_size_distribution,
    generate_slimming_report,
    SizeDistribution,
    CacheFinding,
    MergeSuggestion,
    build_analysis_summary,
    AnalysisSummary,
)


def _format_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(size) < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def _print_header(title: str) -> None:
    width = 80
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def _print_subheader(title: str) -> None:
    print()
    print(f"  ── {title} ──")
    print()


def _print_layer_details(image: ImageInfo) -> None:
    _print_header(f"Docker Image Layer Analysis: {image.name}")

    print(f"  Tags:   {', '.join(image.tags) if image.tags else 'N/A'}")
    print(f"  Layers: {len(image.layers)}")
    print(f"  Total:  {_format_size(image.total_size)}")

    for i, layer in enumerate(image.layers):
        _print_subheader(f"Layer {i + 1}/{len(image.layers)}: {layer.id[:16]}...")

        print(f"  Diff ID:    {layer.diff_id}")
        print(f"  Size:       {_format_size(layer.size)}")
        print(f"  Created At: {layer.created_at[:19] if layer.created_at else 'N/A'}")
        print(f"  Created By:")

        cmd = layer.created_by
        if cmd:
            if cmd.startswith("/bin/sh -c "):
                display_cmd = cmd[len("/bin/sh -c "):]
            else:
                display_cmd = cmd
            for line in display_cmd.split("&&"):
                line = line.strip()
                if line:
                    print(f"    {line}")
        else:
            print(f"    (base layer or imported)")

        print()
        print(f"  File Changes:")
        print(f"    + Added:    {len(layer.added_files)}")
        print(f"    ~ Modified: {len(layer.modified_files)}")
        print(f"    - Deleted:  {len(layer.deleted_files)}")

        if layer.added_files:
            print()
            print(f"    Added files (showing up to 20):")
            for f in sorted(layer.added_files)[:20]:
                print(f"      + {f}")
            if len(layer.added_files) > 20:
                print(f"      ... and {len(layer.added_files) - 20} more")

        if layer.modified_files:
            print()
            print(f"    Modified files (showing up to 20):")
            for f in sorted(layer.modified_files)[:20]:
                print(f"      ~ {f}")
            if len(layer.modified_files) > 20:
                print(f"      ... and {len(layer.modified_files) - 20} more")

        if layer.deleted_files:
            print()
            print(f"    Deleted files (showing up to 20):")
            for f in sorted(layer.deleted_files)[:20]:
                print(f"      - {f}")
            if len(layer.deleted_files) > 20:
                print(f"      ... and {len(layer.deleted_files) - 20} more")


def _print_size_distribution(distributions: List[SizeDistribution], total_size: int) -> None:
    _print_header("Size Distribution")

    print(f"  {'Layer':<20} {'Size':>12} {'%':>8}  {'Distribution'}")
    print(f"  {'─' * 20} {'─' * 12} {'─' * 8}  {'─' * 50}")

    for d in distributions:
        print(f"  {d.layer_id[:18]:<20} {_format_size(d.size):>12} {d.percentage:>7.1f}%  {d.bar}")

    print()
    print(f"  {'TOTAL':<20} {_format_size(total_size):>12} {'100.0%':>8}")


def _print_duplicates(duplicates: Dict[str, List[Tuple[int, int, str]]], waste: int) -> None:
    _print_header("Duplicate Files Across Layers")

    if not duplicates:
        print()
        print("  No duplicate files found across layers.")
        return

    sorted_dups = sorted(duplicates.items(), key=lambda x: sum(o[1] for o in x[1]), reverse=True)

    print()
    print(f"  Found {len(duplicates)} file(s) overwritten in later layers")
    print(f"  Estimated wasted space: {_format_size(waste)}")
    print()

    for path, occurrences in sorted_dups[:30]:
        print(f"  {path}")
        for layer_idx, size, layer_id in occurrences:
            print(f"    Layer {layer_idx + 1} ({layer_id[:12]}...): {_format_size(size)}")
        print()

    if len(sorted_dups) > 30:
        print(f"  ... and {len(sorted_dups) - 30} more duplicate files")


def _print_slimming_report(report: SlimmingReport, image: ImageInfo) -> None:
    _print_header("Slimming Suggestions")

    if report.total_potential_saving == 0 and not report.cache_findings and not report.merge_suggestions:
        print()
        print("  No optimization opportunities detected. Image looks clean!")
        return

    print()
    print(f"  Estimated potential saving: {_format_size(report.total_potential_saving)}")
    print(f"    - Duplicate waste:  {_format_size(report.duplicate_waste)}")
    print(f"    - Cache files:      {_format_size(report.total_cache_size)}")

    if report.cache_findings:
        _print_subheader("Cache / Temporary Files Found")

        by_category: Dict[str, List[CacheFinding]] = defaultdict(list)
        for cf in report.cache_findings:
            by_category[cf.category].append(cf)

        for category, findings in sorted(by_category.items(), key=lambda x: sum(f.size for f in x[1]), reverse=True):
            cat_size = sum(f.size for f in findings)
            print(f"  [{category}] - {len(findings)} file(s), {_format_size(cat_size)}")
            for f in findings[:5]:
                print(f"    {f.path} ({_format_size(f.size)})")
            if len(findings) > 5:
                print(f"    ... and {len(findings) - 5} more")
            print()

        print(f"  Suggestion: Clean caches in the same RUN step that creates them.")
        print(f"  Example:")
        print(f'    RUN apt-get update && apt-get install -y ... && rm -rf /var/lib/apt/lists/*')
        print(f'    RUN pip install --no-cache-dir ...')
        print(f'    RUN npm install --production && npm cache clean --force')

    if report.merge_suggestions:
        _print_subheader("Mergeable Layers")

        for s in report.merge_suggestions:
            layer_nums = [idx + 1 for idx in s.layer_indices]
            print(f"  Layers {layer_nums}: {s.reason}")
            print(f"    Potential saving: {_format_size(s.potential_saving)}")
            print()

        print(f"  Suggestion: Combine commands into a single RUN instruction to reduce layers.")
        print(f"  Example:")
        print(f'    RUN apt-get update && apt-get install -y <packages> && rm -rf /var/lib/apt/lists/*')

    if report.duplicate_waste > 0:
        _print_subheader("Duplicate File Waste")

        print(f"  {_format_size(report.duplicate_waste)} wasted by files overwritten in later layers.")
        print(f"  Suggestion: Avoid copying/creating files that get overwritten.")
        print(f"  Use multi-stage builds to prevent build artifacts from reaching final image.")


def _print_summary(summary: AnalysisSummary, total_size: int, total_potential: int) -> None:
    _print_header("Analysis Summary by Issue Type")

    _print_subheader("🔹 Layer Size Hotspots (Top Layers)")
    print(f"  {'Rank':<5} {'Layer':<22} {'Size':>12} {'%':>8}  {'Comment'}")
    print(f"  {'─' * 5} {'─' * 22} {'─' * 12} {'─' * 8}  {'─' * 30}")
    labels = ["🥇 1st largest", "🥈 2nd largest", "🥉 3rd largest", "4th", "5th"]
    for rank, (idx, lid, size, pct) in enumerate(summary.largest_layers):
        comment = f"Focus: {_format_size(size)} occupies {pct:.1f}% of total"
        print(f"  {labels[rank]:<5} L{idx + 1}:{lid[:18]:<19} {_format_size(size):>12} {pct:>7.1f}%  {comment}")

    if summary.cache_ranking_by_layer:
        _print_subheader("🔹 Cache-Heavy Layers (Files most concentrated)")
        print(f"  {'Layer':<18} {'Cache Files':<14} {'Cache Size':>12} {'% of Layer':>11}  {'Top Category'}")
        print(f"  {'─' * 18} {'─' * 14} {'─' * 12} {'─' * 11}  {'─' * 30}")
        for r in summary.cache_ranking_by_layer:
            top_cat = r.top_categories[0][0] if r.top_categories else "-"
            print(
                f"  L{r.layer_index + 1}:{r.layer_id[:15]:<15} "
                f"{r.cache_count:<14} {_format_size(r.cache_size):>12} {r.cache_ratio:>10.1f}%  "
                f"{top_cat}"
            )

    if summary.cache_ranking_by_category:
        _print_subheader("🔹 Cache Categories by Waste")
        print(f"  {'Category':<32} {'Files':>7} {'Waste Size':>12}")
        print(f"  {'─' * 32} {'─' * 7} {'─' * 12}")
        for cat, count, size in summary.cache_ranking_by_category:
            print(f"  {cat[:32]:<32} {count:>7} {_format_size(size):>12}")

    if summary.duplicate_path_ranking:
        _print_subheader("🔹 Most-Wasted Duplicate Paths")
        print(f"  {'Path':<50} {'Occ':>4} {'Wasted':>12} {'Max Size':>12} {'Layers'}")
        print(f"  {'─' * 50} {'─' * 4} {'─' * 12} {'─' * 12} {'─' * 12}")
        for r in summary.duplicate_path_ranking[:10]:
            layers_str = ",".join(f"L{l + 1}" for l in r.layers_involved)
            path_display = r.path if len(r.path) <= 50 else "..." + r.path[-47:]
            print(
                f"  {path_display:<50} {r.occurrences:>4} "
                f"{_format_size(r.total_wasted_bytes):>12} {_format_size(r.max_size):>12} {layers_str}"
            )

    if summary.layer_activity_ranking:
        _print_subheader("🔹 Most Active Layers (by changes/bytes added)")
        print(f"  {'Layer':<22} {'Changes':>8} {'+ Added':>8} {'~ Mod':>6} {'- Del':>6} {'Added Bytes':>12}")
        print(f"  {'─' * 22} {'─' * 8} {'─' * 8} {'─' * 6} {'─' * 6} {'─' * 12}")
        for r in summary.layer_activity_ranking:
            print(
                f"  L{r.layer_index + 1}:{r.layer_id[:19]:<19} "
                f"{r.total_changes:>8} {r.added_count:>8} {r.modified_count:>6} "
                f"{r.deleted_count:>6} {_format_size(r.added_bytes):>12}"
            )

    if summary.mergeable_layer_groups:
        _print_subheader("🔹 Mergeable Layer Groups (High Impact First)")
        print(f"  {'Layers':<18} {'Potential Saving':>16}  Reason")
        print(f"  {'─' * 18} {'─' * 16}  {'─' * 40}")
        for layer_idx, reason, saving in summary.mergeable_layer_groups[:5]:
            layers_str = ",".join(f"L{i + 1}" for i in layer_idx)
            print(f"  {layers_str:<18} {_format_size(saving):>16}  {reason}")

    _print_subheader("📊 Overall Snapshot")
    print(f"  Total image size:       {_format_size(total_size)}")
    print(f"  Potential space save:   {_format_size(total_potential)}" +
          (f" ({total_potential / total_size * 100:.1f}% of total)" if total_size > 0 else ""))
    print()
    print(f"  🎯 Action priorities:")
    top_actions = []
    if summary.cache_ranking_by_category:
        top_cat = summary.cache_ranking_by_category[0]
        top_actions.append(f"1. Clean {top_cat[0]} ({_format_size(top_cat[2])} savable)")
    if summary.duplicate_path_ranking:
        top_dup = summary.duplicate_path_ranking[0]
        top_actions.append(f"2. Eliminate overwrite of '{top_dup.path[:40]}' ({_format_size(top_dup.total_wasted_bytes)})")
    if summary.mergeable_layer_groups:
        top_merge = summary.mergeable_layer_groups[0]
        layers = ",".join(f"L{i + 1}" for i in top_merge[0])
        top_actions.append(f"3. Merge {layers} → {_format_size(top_merge[2])} saved")
    for act in top_actions:
        print(f"     {act}")
    if not top_actions:
        print(f"     ✅ No significant issues detected.")


def _is_tar_file(path: str) -> bool:
    return path.lower().endswith(".tar") or path.lower().endswith(".tar.gz")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Docker Image Layer Analyzer - Analyze layers, detect duplicates, and suggest optimizations",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s nginx:latest
  %(prog)s python:3.11-slim
  %(prog)s ./saved-image.tar
  %(prog)s myimage:v1 --no-duplicates
        """,
    )
    parser.add_argument(
        "image",
        help="Docker image name (e.g., nginx:latest) or path to a .tar file saved with 'docker save'",
    )
    parser.add_argument(
        "--no-duplicates",
        action="store_true",
        help="Skip duplicate file analysis (faster for large images)",
    )
    parser.add_argument(
        "--no-slimming",
        action="store_true",
        help="Skip slimming suggestions",
    )
    parser.add_argument(
        "--keep-tar",
        action="store_true",
        help="Keep the intermediate tar file when pulling from Docker daemon",
    )

    args = parser.parse_args()

    tar_path = None
    cleanup_tar = False

    try:
        if _is_tar_file(args.image) and os.path.isfile(args.image):
            tar_path = args.image
            print(f"Analyzing tar file: {args.image}")
        elif os.path.isfile(args.image):
            print(f"Error: File '{args.image}' is not a .tar file.", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"Pulling image from Docker daemon: {args.image}")
            try:
                tar_path = save_image_from_docker(args.image)
                cleanup_tar = not args.keep_tar
            except RuntimeError as e:
                print(f"Error: {e}", file=sys.stderr)
                print("Make sure Docker is running and the image exists.", file=sys.stderr)
                sys.exit(1)

        print("Parsing image layers...")
        image = parse_image_tar(tar_path)

        print("Analyzing layer differences...")
        analyze_layer_diffs(image)

        _print_layer_details(image)

        distributions = calculate_size_distribution(image)
        _print_size_distribution(distributions, image.total_size)

        if not args.no_duplicates:
            print("Detecting duplicate files...")
            duplicates = find_duplicate_files(image)
            waste = calculate_duplicate_waste(duplicates)
            _print_duplicates(duplicates, waste)
        else:
            duplicates = {}
            waste = 0

        if not args.no_slimming:
            print("Generating slimming suggestions...")
            report = generate_slimming_report(image, duplicates, waste)
            _print_slimming_report(report, image)

        print("Building summary...")
        if not args.no_slimming:
            summary = build_analysis_summary(
                image, report.cache_findings, duplicates, report.merge_suggestions
            )
            potential = report.total_potential_saving
        else:
            from .analyzer import find_cache_files, find_mergeable_layers
            cf = find_cache_files(image) if not args.no_slimming else []
            ms = find_mergeable_layers(image) if not args.no_slimming else []
            summary = build_analysis_summary(image, cf, duplicates, ms)
            potential = 0
        _print_summary(summary, image.total_size, potential)

        print()
        print("=" * 80)
        print("  Analysis complete!")
        print("=" * 80)

    finally:
        if cleanup_tar and tar_path and os.path.isfile(tar_path):
            os.unlink(tar_path)


if __name__ == "__main__":
    main()
