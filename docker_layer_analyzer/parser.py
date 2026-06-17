import json
import os
import tarfile
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class FileEntry:
    path: str
    size: int
    type: str
    mode: int
    mtime: int


@dataclass
class LayerInfo:
    id: str
    diff_id: str
    size: int
    created_by: str
    created_at: str
    files: List[FileEntry] = field(default_factory=list)
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)


@dataclass
class ImageInfo:
    name: str
    tags: List[str]
    total_size: int
    layers: List[LayerInfo]
    config: dict


def _normpath(path: str) -> str:
    return path.replace("\\", "/")


def _parse_whiteout_name(filename: str) -> Optional[Tuple[str, bool]]:
    filename = _normpath(filename)
    parts = filename.rsplit("/", 1)
    if len(parts) == 1:
        basename = parts[0]
        dirname = ""
    else:
        dirname, basename = parts[0], parts[1]
    if basename == ".wh..wh..opq":
        return dirname if dirname else "/", True
    if basename.startswith(".wh."):
        original = basename[4:]
        original_path = f"{dirname}/{original}" if dirname else original
        return original_path, False
    return None


def _extract_layer_files(layer_tar) -> List[FileEntry]:
    files = []
    for member in layer_tar.getmembers():
        if member.isdir():
            continue
        files.append(FileEntry(
            path=_normpath(member.name),
            size=member.size,
            type="dir" if member.isdir() else ("link" if member.issym() or member.islnk() else "file"),
            mode=member.mode,
            mtime=member.mtime,
        ))
    return files


def parse_image_tar(tar_path: str) -> ImageInfo:
    image_tar = tarfile.open(tar_path, "r")
    try:
        manifest_data = None
        config_data = None
        layer_tars = {}

        for member in image_tar.getmembers():
            if member.name == "manifest.json":
                f = image_tar.extractfile(member)
                manifest_data = json.load(f)
            elif member.name == "repositories":
                pass

        if manifest_data is None:
            raise ValueError("manifest.json not found in image tar")

        manifest = manifest_data[0]
        config_file = manifest["Config"]
        layer_paths = manifest.get("Layers", [])
        repo_tags = manifest.get("RepoTags", [])

        config_member = image_tar.getmember(config_file)
        config_f = image_tar.extractfile(config_member)
        config_data = json.load(config_f)

        history = config_data.get("history", [])
        rootfs = config_data.get("rootfs", {})
        diff_ids = rootfs.get("diff_ids", [])

        layers = []
        for i, layer_path in enumerate(layer_paths):
            layer_member = image_tar.getmember(layer_path)
            layer_size = layer_member.size

            diff_id = diff_ids[i] if i < len(diff_ids) else f"unknown_{i}"

            hist_entry = None
            hist_idx = 0
            empty_layer_count = 0
            for h in history:
                if h.get("empty_layer", False):
                    empty_layer_count += 1
                    continue
                if hist_idx == i:
                    hist_entry = h
                    break
                hist_idx += 1

            created_by = ""
            created_at = ""
            if hist_entry:
                created_by = hist_entry.get("created_by", "")
                created_at = hist_entry.get("created", "")

            layer_f = image_tar.extractfile(layer_member)
            layer_tar_obj = tarfile.open(fileobj=layer_f, mode="r")
            try:
                files = _extract_layer_files(layer_tar_obj)
            finally:
                layer_tar_obj.close()

            layer_id = os.path.dirname(layer_path) if "/" in layer_path else f"layer_{i}"

            layers.append(LayerInfo(
                id=layer_id,
                diff_id=diff_id,
                size=layer_size,
                created_by=created_by,
                created_at=created_at,
                files=files,
            ))

        total_size = sum(l.size for l in layers)

        image_name = repo_tags[0] if repo_tags else os.path.basename(tar_path)

        return ImageInfo(
            name=image_name,
            tags=repo_tags,
            total_size=total_size,
            layers=layers,
            config=config_data,
        )
    finally:
        image_tar.close()


def save_image_from_docker(image_name: str, output_path: Optional[str] = None) -> str:
    import subprocess

    if output_path is None:
        fd, output_path = tempfile.mkstemp(suffix=".tar")
        os.close(fd)

    safe_name = image_name.replace(":", "_").replace("/", "_")
    cmd = ["docker", "save", "-o", output_path, image_name]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"docker save failed: {result.stderr}")

    return output_path
