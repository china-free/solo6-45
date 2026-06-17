import os
from typing import Dict, List, Set, Tuple

from .parser import FileEntry, ImageInfo, LayerInfo, _parse_whiteout_name


def analyze_layer_diffs(image: ImageInfo) -> None:
    previous_files: Dict[str, FileEntry] = {}

    for layer in image.layers:
        added = []
        modified = []
        deleted = []
        current_files: Dict[str, FileEntry] = {}

        opaque_dirs: Set[str] = set()

        for f in layer.files:
            whiteout = _parse_whiteout_name(f.path)
            if whiteout is not None:
                target_path, is_opaque = whiteout
                if is_opaque:
                    opaque_dirs.add(target_path)
                else:
                    deleted.append(target_path)
                continue

            current_files[f.path] = f

        for opaque_dir in opaque_dirs:
            prefix = opaque_dir + "/"
            paths_to_delete = [p for p in previous_files if p == opaque_dir or p.startswith(prefix)]
            for p in paths_to_delete:
                deleted.append(p)

        for path, entry in current_files.items():
            skipped = False
            for opaque_dir in opaque_dirs:
                if path == opaque_dir or path.startswith(opaque_dir + "/"):
                    skipped = True
                    break
            if skipped:
                continue

            if path in previous_files:
                prev = previous_files[path]
                if entry.size != prev.size or entry.mtime != prev.mtime:
                    modified.append(path)
            else:
                added.append(path)

        layer.added_files = added
        layer.modified_files = modified
        layer.deleted_files = deleted

        for path in deleted:
            previous_files.pop(path, None)
        previous_files.update(current_files)


def find_duplicate_files(image: ImageInfo) -> Dict[str, List[Tuple[int, int, str]]]:
    file_layers: Dict[str, List[Tuple[int, int, str]]] = {}

    for i, layer in enumerate(image.layers):
        all_changed = set(layer.added_files + layer.modified_files)
        for f in layer.files:
            whiteout = _parse_whiteout_name(f.path)
            if whiteout is not None:
                continue
            if f.path in all_changed:
                if f.path not in file_layers:
                    file_layers[f.path] = []
                file_layers[f.path].append((i, f.size, layer.id))

    duplicates = {}
    for path, occurrences in file_layers.items():
        if len(occurrences) > 1:
            duplicates[path] = occurrences

    return duplicates


def calculate_duplicate_waste(duplicates: Dict[str, List[Tuple[int, int, str]]]) -> int:
    waste = 0
    for path, occurrences in duplicates.items():
        for i in range(1, len(occurrences)):
            waste += occurrences[i][1]
    return waste
