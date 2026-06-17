import io
import json
import os
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from docker_layer_analyzer.parser import parse_image_tar, LayerInfo, ImageInfo, _parse_whiteout_name
from docker_layer_analyzer.differ import analyze_layer_diffs, find_duplicate_files, calculate_duplicate_waste
from docker_layer_analyzer.analyzer import (
    calculate_size_distribution,
    find_cache_files,
    generate_slimming_report,
    build_analysis_summary,
    AnalysisSummary,
    LayerCacheRanking,
    DuplicatePathRanking,
    LayerActivityRanking,
)


def _add_file_to_tar(tar, path, content=b"", mode=0o644):
    info = tarfile.TarInfo(name=path)
    info.size = len(content)
    info.mode = mode
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(content))


def _add_dir_to_tar(tar, path, mode=0o755):
    info = tarfile.TarInfo(name=path)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    tar.addfile(info)


def _add_whiteout_to_tar(tar, dir_path, filename):
    wh_name = f"{dir_path}/.wh.{filename}"
    _add_file_to_tar(tar, wh_name, b"")


def _add_opaque_whiteout_to_tar(tar, dir_path):
    wh_name = f"{dir_path}/.wh..wh..opq"
    _add_file_to_tar(tar, wh_name, b"")


def _create_layer_tar(files_dict):
    buf = io.BytesIO()
    tar = tarfile.open(fileobj=buf, mode="w")
    for path, content in files_dict.items():
        if isinstance(content, bytes):
            _add_file_to_tar(tar, path, content)
        elif content == "DIR":
            _add_dir_to_tar(tar, path)
    tar.close()
    buf.seek(0)
    return buf


def _build_test_image_tar(path):
    layer1_files = {
        "etc": "DIR",
        "etc/config.yml": b"key: value\n",
        "usr": "DIR",
        "usr/bin": "DIR",
        "usr/bin/app": b"#!/bin/sh\necho hello\n" * 100,
        "var": "DIR",
        "var/cache/apt": "DIR",
        "var/cache/apt/archives": "DIR",
        "var/cache/apt/archives/pkg1.deb": b"X" * 5000,
        "var/cache/apt/archives/pkg2.deb": b"Y" * 3000,
        "var/lib/apt": "DIR",
        "var/lib/apt/lists": "DIR",
        "var/lib/apt/lists/idx.txt": b"index data\n",
        "tmp": "DIR",
        "tmp/build.log": b"build output\n" * 50,
    }

    layer2_files = {
        "etc": "DIR",
        "etc/config.yml": b"key: new_value\nupdated: true\n",
        "usr": "DIR",
        "usr/bin": "DIR",
        "usr/bin/app": b"#!/bin/sh\necho hello v2\n" * 120,
        "usr": "DIR",
        "usr/local": "DIR",
        "usr/local/lib": "DIR",
        "usr/local/lib/newlib.so": b"Z" * 8000,
        "var": "DIR",
        "var/cache/apt": "DIR",
        "var/cache/apt/archives": "DIR",
        "var/cache/apt/archives/pkg3.deb": b"W" * 4000,
        "tmp": "DIR",
        "tmp/.wh.build.log": b"",
    }

    layer3_files = {
        "app": "DIR",
        "app/data.txt": b"important data\n",
        "root": "DIR",
        "root/.npm": "DIR",
        "root/.npm/_cacache": "DIR",
        "root/.npm/_cacache/content-v2": "DIR",
        "root/.npm/_cacache/content-v2/abc": b"C" * 2000,
    }

    layers = [layer1_files, layer2_files, layer3_files]
    layer_digests = ["sha256:aaa111", "sha256:bbb222", "sha256:ccc333"]

    image_tar = tarfile.open(path, "w")

    config = {
        "config": {"Cmd": ["/bin/sh"]},
        "history": [
            {
                "created": "2025-01-01T00:00:00Z",
                "created_by": "/bin/sh -c apt-get update && apt-get install -y pkg1 pkg2",
                "comment": "",
            },
            {
                "created": "2025-01-01T00:01:00Z",
                "created_by": "/bin/sh -c apt-get install -y pkg3 && cp /usr/bin/app /usr/bin/app",
                "comment": "",
            },
            {
                "created": "2025-01-01T00:02:00Z",
                "created_by": "/bin/sh -c npm install && npm cache clean --force",
                "comment": "",
            },
        ],
        "rootfs": {
            "type": "layers",
            "diff_ids": layer_digests,
        },
    }

    config_json = json.dumps(config, indent=2).encode()
    config_hash = "sha256_abc123"
    config_filename = f"{config_hash}.json"
    _add_file_to_tar(image_tar, config_filename, config_json)

    layer_filenames = []
    for i, layer_files in enumerate(layers):
        layer_buf = _create_layer_tar(layer_files)
        digest = layer_digests[i].replace(":", "_")
        layer_dir = digest
        layer_filename = f"{layer_dir}/layer.tar"
        layer_filenames.append(layer_filename)

        info = tarfile.TarInfo(name=layer_filename)
        layer_data = layer_buf.getvalue()
        info.size = len(layer_data)
        info.type = tarfile.REGTYPE
        image_tar.addfile(info, io.BytesIO(layer_data))

    manifest = [
        {
            "Config": config_filename,
            "RepoTags": ["test-image:latest"],
            "Layers": layer_filenames,
        }
    ]
    _add_file_to_tar(image_tar, "manifest.json", json.dumps(manifest).encode())

    image_tar.close()


class TestWhiteoutParsing(unittest.TestCase):
    def test_regular_whiteout(self):
        result = _parse_whiteout_name("etc/.wh.config.yml")
        self.assertEqual(result, ("etc/config.yml", False))

    def test_opaque_whiteout(self):
        result = _parse_whiteout_name("tmp/.wh..wh..opq")
        self.assertEqual(result, ("tmp", True))

    def test_root_opaque_whiteout(self):
        result = _parse_whiteout_name(".wh..wh..opq")
        self.assertEqual(result, ("/", True))

    def test_non_whiteout(self):
        result = _parse_whiteout_name("etc/config.yml")
        self.assertIsNone(result)


class TestImageParser(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_parse_image_basic(self):
        image = parse_image_tar(self.tar_path)
        self.assertEqual(image.name, "test-image:latest")
        self.assertEqual(len(image.layers), 3)
        self.assertGreater(image.total_size, 0)

    def test_layer_sizes(self):
        image = parse_image_tar(self.tar_path)
        for layer in image.layers:
            self.assertGreater(layer.size, 0)

    def test_layer_history(self):
        image = parse_image_tar(self.tar_path)
        self.assertIn("apt-get update", image.layers[0].created_by)
        self.assertIn("apt-get install", image.layers[1].created_by)
        self.assertIn("npm install", image.layers[2].created_by)


class TestLayerDiff(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)
        analyze_layer_diffs(self.image)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_added_files_first_layer(self):
        layer0 = self.image.layers[0]
        self.assertGreater(len(layer0.added_files), 0)
        self.assertIn("etc/config.yml", layer0.added_files)
        self.assertIn("usr/bin/app", layer0.added_files)

    def test_modified_files(self):
        layer1 = self.image.layers[1]
        self.assertIn("etc/config.yml", layer1.modified_files)
        self.assertIn("usr/bin/app", layer1.modified_files)

    def test_deleted_files(self):
        layer1 = self.image.layers[1]
        self.assertIn("tmp/build.log", layer1.deleted_files)

    def test_new_files_in_layer2(self):
        layer1 = self.image.layers[1]
        self.assertIn("usr/local/lib/newlib.so", layer1.added_files)
        self.assertIn("var/cache/apt/archives/pkg3.deb", layer1.added_files)

    def test_layer3_additions(self):
        layer2 = self.image.layers[2]
        self.assertIn("app/data.txt", layer2.added_files)


class TestDuplicates(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)
        analyze_layer_diffs(self.image)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_duplicate_detection(self):
        dups = find_duplicate_files(self.image)
        self.assertIn("etc/config.yml", dups)
        self.assertIn("usr/bin/app", dups)
        self.assertEqual(len(dups["etc/config.yml"]), 2)

    def test_duplicate_waste(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        self.assertGreater(waste, 0)


class TestSizeDistribution(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_distribution_sums_to_100(self):
        dist = calculate_size_distribution(self.image)
        total_pct = sum(d.percentage for d in dist)
        self.assertAlmostEqual(total_pct, 100.0, places=1)


class TestCacheFiles(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_apt_cache_found(self):
        findings = find_cache_files(self.image)
        categories = {f.category for f in findings}
        self.assertIn("apt cache (.deb packages)", categories)

    def test_npm_cache_found(self):
        findings = find_cache_files(self.image)
        categories = {f.category for f in findings}
        self.assertIn("npm cache", categories)

    def test_apt_lists_found(self):
        findings = find_cache_files(self.image)
        categories = {f.category for f in findings}
        self.assertIn("apt lists", categories)


class TestSlimmingReport(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)
        analyze_layer_diffs(self.image)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_report_has_findings(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        report = generate_slimming_report(self.image, dups, waste)
        self.assertGreater(len(report.cache_findings), 0)
        self.assertGreater(report.total_cache_size, 0)

    def test_merge_suggestions(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        report = generate_slimming_report(self.image, dups, waste)
        self.assertGreater(len(report.merge_suggestions), 0)
        for s in report.merge_suggestions:
            self.assertGreater(len(s.involved_files), 0)

    def test_no_double_counting(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        report = generate_slimming_report(self.image, dups, waste)

        cache = report.total_cache_size
        dup = report.duplicate_waste
        merge = sum(s.potential_saving for s in report.merge_suggestions)
        total = report.total_potential_saving

        self.assertEqual(total, cache + dup + merge)

        raw_cache = sum(c.size for c in report.cache_findings)
        self.assertGreaterEqual(raw_cache, cache)

        raw_merge_total = 0
        for s in report.merge_suggestions:
            raw_merge_total += sum(f[2] for f in s.involved_files)
        self.assertGreaterEqual(raw_merge_total, merge)

    def test_deduplication_accuracy(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        report = generate_slimming_report(self.image, dups, waste)

        cache_files = {(c.layer_index, c.path): c.size for c in report.cache_findings}

        counted = set()
        expected_cache = 0
        for (li, path), size in cache_files.items():
            if (li, path) not in counted:
                counted.add((li, path))
                expected_cache += size

        self.assertEqual(report.total_cache_size, expected_cache)

        expected_dup = 0
        for path, occurrences in dups.items():
            for i in range(1, len(occurrences)):
                layer_idx, size, _ = occurrences[i]
                if (layer_idx, path) not in counted:
                    counted.add((layer_idx, path))
                    expected_dup += size

        self.assertEqual(report.duplicate_waste, expected_dup)

        expected_merge = 0
        for s in report.merge_suggestions:
            for layer_idx, file_path, file_size in s.involved_files:
                if (layer_idx, file_path) not in counted:
                    counted.add((layer_idx, file_path))
                    expected_merge += file_size

        total_merge = sum(s.potential_saving for s in report.merge_suggestions)
        self.assertEqual(total_merge, expected_merge)

        self.assertEqual(report.total_potential_saving, expected_cache + expected_dup + expected_merge)

    def test_merge_suggestion_involved_files_structure(self):
        dups = find_duplicate_files(self.image)
        waste = calculate_duplicate_waste(dups)
        report = generate_slimming_report(self.image, dups, waste)

        for s in report.merge_suggestions:
            self.assertIsInstance(s.involved_files, list)
            for item in s.involved_files:
                self.assertEqual(len(item), 3)
                self.assertIsInstance(item[0], int)
                self.assertIsInstance(item[1], str)
                self.assertIsInstance(item[2], int)


class TestAnalysisSummary(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.tar_path = os.path.join(self.tmpdir, "test-image.tar")
        _build_test_image_tar(self.tar_path)
        self.image = parse_image_tar(self.tar_path)
        analyze_layer_diffs(self.image)
        self.duplicates = find_duplicate_files(self.image)
        self.waste = calculate_duplicate_waste(self.duplicates)
        self.report = generate_slimming_report(self.image, self.duplicates, self.waste)
        self.summary = build_analysis_summary(
            self.image,
            self.report.cache_findings,
            self.duplicates,
            self.report.merge_suggestions,
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_summary_is_analysis_summary_type(self):
        self.assertIsInstance(self.summary, AnalysisSummary)

    def test_largest_layers_ranking(self):
        self.assertGreater(len(self.summary.largest_layers), 0)
        prev_size = float("inf")
        for idx, lid, size, pct in self.summary.largest_layers:
            self.assertLessEqual(size, prev_size)
            prev_size = size
            self.assertIsInstance(idx, int)
            self.assertIsInstance(size, int)
            self.assertIsInstance(pct, float)
            self.assertGreater(pct, 0)

    def test_largest_layers_sum_sanity(self):
        total_pct = sum(x[3] for x in self.summary.largest_layers)
        self.assertLessEqual(total_pct, 100.0)

    def test_cache_ranking_by_layer_structure(self):
        self.assertGreater(len(self.summary.cache_ranking_by_layer), 0)
        for r in self.summary.cache_ranking_by_layer:
            self.assertIsInstance(r, LayerCacheRanking)
            self.assertGreaterEqual(r.cache_count, 1)
            self.assertGreaterEqual(r.cache_size, 0)
            self.assertIsInstance(r.layer_index, int)
            self.assertIsInstance(r.top_categories, list)

    def test_cache_ranking_by_layer_sorted(self):
        prev_size = float("inf")
        for r in self.summary.cache_ranking_by_layer:
            self.assertLessEqual(r.cache_size, prev_size)
            prev_size = r.cache_size

    def test_cache_ranking_by_category(self):
        self.assertGreater(len(self.summary.cache_ranking_by_category), 0)
        for cat, count, size in self.summary.cache_ranking_by_category:
            self.assertIsInstance(cat, str)
            self.assertGreaterEqual(count, 1)
            self.assertGreaterEqual(size, 0)

    def test_cache_ranking_by_category_sorted(self):
        prev_size = float("inf")
        for _, _, size in self.summary.cache_ranking_by_category:
            self.assertLessEqual(size, prev_size)
            prev_size = size

    def test_duplicate_path_ranking_structure(self):
        self.assertGreater(len(self.summary.duplicate_path_ranking), 0)
        for r in self.summary.duplicate_path_ranking:
            self.assertIsInstance(r, DuplicatePathRanking)
            self.assertGreaterEqual(r.occurrences, 2)
            self.assertGreaterEqual(r.total_wasted_bytes, 0)
            self.assertGreater(r.max_size, 0)
            self.assertEqual(len(r.layers_involved), r.occurrences)

    def test_duplicate_path_ranking_sorted(self):
        prev_waste = float("inf")
        for r in self.summary.duplicate_path_ranking:
            self.assertLessEqual(r.total_wasted_bytes, prev_waste)
            prev_waste = r.total_wasted_bytes

    def test_layer_activity_ranking(self):
        self.assertEqual(len(self.summary.layer_activity_ranking), len(self.image.layers))
        for r in self.summary.layer_activity_ranking:
            self.assertIsInstance(r, LayerActivityRanking)
            self.assertIsInstance(r.total_changes, int)
            self.assertEqual(
                r.total_changes,
                r.added_count + r.modified_count + r.deleted_count,
            )

    def test_mergeable_layer_groups(self):
        self.assertGreater(len(self.summary.mergeable_layer_groups), 0)
        for indices, reason, saving in self.summary.mergeable_layer_groups:
            self.assertIsInstance(indices, list)
            self.assertGreaterEqual(len(indices), 2)
            self.assertIsInstance(reason, str)
            self.assertIsInstance(saving, int)

    def test_largest_layer_contains_layer1_or_layer2(self):
        top_idx = self.summary.largest_layers[0][0]
        self.assertIn(top_idx, [0, 1])

    def test_cache_ranking_apt_cache_category_present(self):
        cats = {cat for cat, _, _ in self.summary.cache_ranking_by_category}
        apt_found = any("apt" in c.lower() for c in cats)
        self.assertTrue(apt_found)

    def test_duplicate_ranking_contains_config_yml(self):
        paths = {r.path for r in self.summary.duplicate_path_ranking}
        self.assertIn("etc/config.yml", paths)
        self.assertIn("usr/bin/app", paths)

    def test_activity_ranking_layer0_has_max_added(self):
        top = self.summary.layer_activity_ranking[0]
        self.assertGreater(top.added_bytes, 0)


if __name__ == "__main__":
    unittest.main()
