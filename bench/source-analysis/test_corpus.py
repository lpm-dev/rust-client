import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import urllib.error
import warnings
import zipfile

import archive_inventory
import archive_pilot

spec = importlib.util.spec_from_file_location("corpus", Path(__file__).with_name("corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)

spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

spec = importlib.util.spec_from_file_location("comparison", Path(__file__).with_name("compare.py"))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)

spec = importlib.util.spec_from_file_location("historical", Path(__file__).with_name("historical.py"))
historical = importlib.util.module_from_spec(spec)
spec.loader.exec_module(historical)

spec = importlib.util.spec_from_file_location(
    "attack_families", Path(__file__).parent / "attack-families" / "prepare.py"
)
attack_families = importlib.util.module_from_spec(spec)
spec.loader.exec_module(attack_families)


class ArchivePilotTests(unittest.TestCase):
    def record(self, number, name, evidence=(), advisory=None):
        return {"sha256": f"{number:064x}", "name": name, "version": "1.0.0", "size_bytes": 10,
                "locations": ["local"], "focus_hints": [], "evidence_hashes": list(evidence),
                "provenance": [{"source": "test", "advisory_id": advisory}]}

    def test_duplicate_archives_keep_all_provenance_and_review_links(self):
        a, b = self.record(1, "one"), self.record(1, "one")
        b.update(review_path="private-review", review_sha256="digest")
        records = archive_inventory.consolidate([a, b])
        self.assertEqual(len(records), 1)
        self.assertEqual(len(records[0]["provenance"]), 2)
        self.assertEqual(records[0]["review_path"], "private-review")

    def test_same_package_with_different_archive_bytes_keeps_both_variants(self):
        records = archive_inventory.consolidate([self.record(1, "one"), self.record(2, "one")])
        self.assertEqual(len(records), 2)
        archive_inventory.assign_splits(records, set())
        self.assertEqual(records[0]["group"], records[1]["group"])

    def test_conflicting_identity_for_identical_bytes_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "conflicting"):
            archive_inventory.consolidate([self.record(1, "one"), self.record(1, "two")])

    def test_transitive_advisory_and_source_links_preserve_prior_exclusion(self):
        records = [self.record(1, "prior", advisory="A"), self.record(2, "two", ["code"], "A"),
                   self.record(3, "three", ["code"])]
        archive_inventory.assign_splits(records, {"prior"})
        self.assertEqual({r["split"] for r in records}, {"prior"})
        self.assertEqual(len({r["group"] for r in records}), 1)

    def test_split_membership_is_independent_of_record_order(self):
        records = [self.record(i, f"package-{i}") for i in range(1, 100)]
        archive_inventory.assign_splits(records, set())
        expected = {r["sha256"]: r["split"] for r in records}
        archive_inventory.assign_splits(records[::-1], set())
        self.assertEqual(expected, {r["sha256"]: r["split"] for r in records})
        self.assertIn("reserved", expected.values())

    def test_public_inventory_omits_private_locations_and_review_paths(self):
        record = self.record(1, "one")
        record["review_path"] = "secret"
        public = archive_inventory.public_record(record)
        self.assertNotIn("locations", public)
        self.assertNotIn("review_path", public)

    def test_zip_root_is_selected_by_package_identity_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as source:
                source.writestr("wrapper/pkg/package.json", json.dumps({"name": "sample", "version": "1"}))
                source.writestr("wrapper/pkg/index.js", "throw new Error('must never execute')")
                source.writestr("metadata.json", "{}")
            target = root / "output"
            target.mkdir()
            stats = archive_pilot.extract_zip(archive, target, {"name": "sample", "version": "1"})
            self.assertEqual(stats["files"], 2)
            self.assertTrue((target / "index.js").is_file())
            self.assertFalse((target / "metadata.json").exists())

    def test_zip_rejects_traversal_even_outside_selected_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as source:
                source.writestr("../outside", "data")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                archive_pilot.extract_zip(archive, root / "output", {"name": "sample", "version": "1"})

    def test_zip_rejects_ambiguous_matching_package_roots(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "sample.zip"
            identity = {"name": "sample", "version": "1"}
            with zipfile.ZipFile(archive, "w") as source:
                for prefix in ("one", "two"):
                    source.writestr(prefix + "/package.json", json.dumps(identity))
            with self.assertRaisesRegex(ValueError, "ambiguous"):
                archive_pilot.extract_zip(archive, Path(temporary) / "output", identity)

    def test_normalized_fingerprints_ignore_literal_and_comment_variants(self):
        self.assertEqual(archive_pilot.normalized_hash("const x = 'one'; // comment\nf(12)"),
                         archive_pilot.normalized_hash('const x="two"; f(42)'))
        self.assertNotEqual(archive_pilot.normalized_hash("f(12)"), archive_pilot.normalized_hash("g(12)"))

    def test_coverage_distinguishes_source_selection_from_unsupported_stages(self):
        for name, expected in [("index.js", "selected_source"), ("install.sh", "unsupported_extension"),
                               (".hidden/a.js", "hidden"), ("node_modules/a.js", "excluded_directory"),
                               ("types.d.ts", "declaration_or_map")]:
            self.assertEqual(archive_pilot.source_reason(Path(name)), expected)

    def test_public_results_remove_payload_excerpts_and_domains(self):
        row = {"analysis": {"meta": {"evidence": [{"ruleId": "fs", "excerpt": "private"}],
                                     "urlDomains": ["private.invalid"]}}}
        archive_pilot.sanitize(row)
        self.assertEqual(row["analysis"]["meta"], {"evidence": [{"ruleId": "fs"}]})


class IncidentReconstructionTests(unittest.TestCase):
    def test_reference_download_rejects_payload_hosts_and_redirects(self):
        for url in ("http://raw.githubusercontent.com/example", "https://payload.invalid/code",
                    "https://user@raw.githubusercontent.com/example",
                    "https://raw.githubusercontent.com:8443/example"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "origin"):
                attack_families.fetch_reference(url)
        self.assertIsNone(attack_families.NoRedirect().redirect_request(
            None, None, 302, "", {}, "https://payload.invalid/code"))

    def test_html_diff_preserves_entities_inline_changes_and_empty_lines(self):
        parser = attack_families.DiffHTML()
        parser.feed('''<div class="d2h-file-wrapper">
          <span class="d2h-file-name"><a>package/entry.js</a></span>
          <td class="d2h-info"><div class="d2h-code-line">@@ -0,0 +1,2 @@</div></td>
          <td class="d2h-ins"><span class="d2h-code-line-ctn">const s = &quot;<ins>a&amp;b</ins>&quot;;</span></td>
          <td class="d2h-ins"><span class="d2h-code-line-ctn"><br></span></td></div>''')
        self.assertEqual(attack_families.apply_hunks("", parser.files["entry.js"]),
                         'const s = "a&b";\n\n')

    def test_html_diff_rejects_parent_paths_and_duplicate_files(self):
        for path in ("package/../outside.js", "package/a\\b.js", "/outside.js"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "unsafe"):
                attack_families.DiffHTML().feed(f'<span class="d2h-file-name">{path}</span>')
        with self.assertRaisesRegex(ValueError, "duplicate"):
            attack_families.DiffHTML().feed(
                '<span class="d2h-file-name">package/a.js</span>' * 2)

    def test_reconstruction_keeps_unchanged_lines_between_hunks(self):
        rows = [("@", "@@ -1,1 +1,1 @@"), ("-", "a"), ("+", "A"),
                ("@", "@@ -3,1 +3,2 @@"), (" ", "c"), ("+", "new")]
        self.assertEqual(attack_families.apply_hunks("a\nb\nc\nd\n", rows), "A\nb\nc\nnew\nd\n")

    def test_reconstruction_rejects_wrong_base_truncated_hunks_and_offsets(self):
        cases = [
            ([("@", "@@ -1,1 +1,1 @@"), (" ", "wrong")], "context"),
            ([("@", "@@ -1,1 +1,2 @@"), (" ", "a")], "line-count"),
            ([("@", "@@ -1,1 +2,1 @@"), (" ", "a")], "offset"),
            ([("@", "@@ -5,1 +5,1 @@"), (" ", "a")], "out-of-range"),
            ([], "missing"),
            ([("@", "unrecognized diff")], "header"),
        ]
        for rows, reason in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                attack_families.apply_hunks("a\n", rows)

    def test_unchanged_diff_preserves_original_line_endings(self):
        self.assertEqual(attack_families.apply_hunks("a\r\nb", [("@", "File without changes")]),
                         "a\r\nb")


class CorpusTests(unittest.TestCase):
    def test_ranking_accepts_legacy_uppercase_package_names(self):
        self.assertIsNotNone(corpus.PACKAGE_NAME.fullmatch("JSONStream"))
        self.assertIsNone(corpus.PACKAGE_NAME.fullmatch("../outside"))

    def test_integrity_requires_the_strongest_supported_digest(self):
        data = b"published package"
        sha1 = base64.b64encode(hashlib.sha1(data).digest()).decode()
        sha512 = base64.b64encode(hashlib.sha512(data).digest()).decode()
        corpus.verify_integrity(data, "sha512-" + sha512)
        with self.assertRaisesRegex(ValueError, "mismatch"):
            corpus.verify_integrity(data, "sha1-" + sha1 + " sha512-invalid")

    def test_family_keeps_related_packages_in_one_split(self):
        self.assertEqual(corpus.family("@babel/parser"), corpus.family("@babel/types"))
        self.assertEqual(corpus.family("lodash.merge"), corpus.family("lodash"))

    def test_expansion_excludes_existing_names_and_preserves_ranking_positions(self):
        selected = corpus.select_ranked_packages(["old", "new", "third"], 2, {"old"})
        self.assertEqual(selected, [(2, "new"), (3, "third")])
        with self.assertRaisesRegex(ValueError, "ranking"):
            corpus.select_ranked_packages(["old", "new"], 2, {"old"})

    def test_validation_has_exact_count_and_no_prior_or_tuning_family_overlap(self):
        names = ["@old/new", "@a/one", "@a/two", "@b/one", "@b/two", "solo"]
        split = corpus.validation_families(names, 3, {"@old"})
        self.assertEqual(sum(corpus.family(n) in split for n in names), 3)
        self.assertNotIn("@old", split)
        self.assertEqual(split, corpus.validation_families(names[::-1], 3, {"@old"}))
        with self.assertRaisesRegex(ValueError, "whole families"):
            corpus.validation_families(["@a/one", "@a/two"], 1, set())
        with self.assertRaisesRegex(ValueError, "positive"):
            corpus.validation_families(names, 0, set())

    def test_fresh_validation_selection_excludes_every_previously_seen_family(self):
        names = ["@old/new", "lodash.more", "fresh", "@new/a", "@new/b"]
        self.assertEqual(corpus.select_ranked_packages(names, 3, set(), {"@old", "lodash"}),
                         [(3, "fresh"), (4, "@new/a"), (5, "@new/b")])

    def test_freeze_records_unavailable_names_and_only_replaces_missing_metadata(self):
        def fetch(url, limit):
            if url == corpus.RANKING_URL:
                return b'export const names = ["gone", "available", "replacement"]'
            name = url.split("/")[-2]
            if name == "gone":
                raise urllib.error.HTTPError(url, 404, "not found", {}, None)
            return json.dumps({"name": name, "version": "1", "dist": {
                "tarball": "https://registry.npmjs.org/a.tgz", "integrity": "sha512-hash"}}).encode()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = SimpleNamespace(count=2, exclude_manifest=None, validation_count=1, workers=2,
                                   replace_unavailable=True, cache=root / "cache", manifest=root / "manifest.json")
            with patch.object(corpus, "fetch", side_effect=fetch), patch("builtins.print"):
                corpus.freeze(args)
            manifest = json.loads(args.manifest.read_text())
            self.assertEqual([p["name"] for p in manifest["packages"]], ["available", "replacement"])
            self.assertEqual(manifest["selection"]["unavailable"], [
                {"name": "gone", "rank": 1, "http_status": 404}])
            error = urllib.error.HTTPError("url", 503, "unavailable", {}, None)
            args.count = 1
            with patch.object(corpus, "fetch", side_effect=[b'export const names = ["a"]', error]):
                with self.assertRaisesRegex(ValueError, "resolution failed"):
                    corpus.freeze(args)

    def test_runner_rejects_missing_reordered_or_mismatched_scanner_results(self):
        packages = [{"name": "a", "version": "1"}, {"name": "b", "version": "2"}]
        rows = [{**p, "analysis": {}} for p in packages]
        runner.validate_rows(packages, rows, 0)
        for invalid in [rows[:1], rows[::-1], [rows[0], rows[0]],
                        [{**rows[0], "version": "2"}, rows[1]], packages]:
            with self.assertRaises(ValueError):
                runner.validate_rows(packages, invalid, 0)
        with self.assertRaises(ValueError):
            runner.validate_rows(packages, rows, 1)

    def test_comparison_keeps_partial_coverage_separate_from_tag_reductions(self):
        before = {("a", "1"): {"analysis": {"source": {"shell": True}, "supplyChain": {}, "manifest": {},
                   "meta": {"filesScanned": 1, "bytesScanned": 30, "unparsedFiles": 1}}}}
        after = {("a", "1"): {"analysis": {"source": {"shell": False}, "supplyChain": {}, "manifest": {},
                  "meta": {"filesScanned": 1, "bytesScanned": 30, "unparsedFiles": 1}}}}
        summary, rows = comparison.compare(before, after)
        self.assertEqual(summary["complete"], {"baseline": 0, "candidate": 0})
        self.assertEqual(rows[0]["removed"], ["source.shell"])
        with self.assertRaises(ValueError):
            comparison.compare(before, {})

    def archive(self, names):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        archive = root / "package.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            for name, kind in names:
                info = tarfile.TarInfo(name)
                info.type = kind
                if kind == tarfile.REGTYPE:
                    info.size = 3
                    tar.addfile(info, io.BytesIO(b"abc"))
                else:
                    info.linkname = "../../outside"
                    tar.addfile(info)
        destination = root / "source"
        destination.mkdir()
        return archive, destination

    def test_extraction_preserves_source_without_executable_permissions(self):
        archive, destination = self.archive([("package/lib/index.js", tarfile.REGTYPE)])
        stats = corpus.extract_archive(archive, destination)
        source = destination / "lib/index.js"
        self.assertEqual(source.read_bytes(), b"abc")
        self.assertEqual(stats, {"files": 1, "expanded_bytes": 3, "identical_duplicates": 0})
        self.assertEqual(source.stat().st_mode & 0o111, 0)

    def test_extraction_accepts_a_consistent_legacy_archive_root(self):
        archive, destination = self.archive([("estree/index.d.ts", tarfile.REGTYPE)])
        corpus.extract_archive(archive, destination)
        self.assertEqual((destination / "index.d.ts").read_bytes(), b"abc")

    def test_extraction_records_identical_duplicate_members(self):
        archive, destination = self.archive([("package/index.js", tarfile.REGTYPE)] * 2)
        stats = corpus.extract_archive(archive, destination)
        self.assertEqual(stats["identical_duplicates"], 1)
        self.assertEqual((destination / "index.js").read_bytes(), b"abc")

    def test_extraction_rejects_conflicting_duplicate_members(self):
        archive, destination = self.archive([])
        with tarfile.open(archive, "w:gz") as tar:
            for data in (b"first", b"second"):
                info = tarfile.TarInfo("package/index.js")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        with self.assertRaisesRegex(ValueError, "conflicting duplicate"):
            corpus.extract_archive(archive, destination)

    def test_extraction_enforces_byte_and_entry_limits(self):
        from unittest.mock import patch
        for setting, limit in (("MAX_EXPANDED", 2), ("MAX_ENTRIES", 0)):
            archive, destination = self.archive([("package/index.js", tarfile.REGTYPE)])
            with patch.object(corpus, setting, limit):
                with self.assertRaisesRegex(ValueError, "limit exceeded"):
                    corpus.extract_archive(archive, destination)

    def test_extraction_rejects_traversal_links_and_mixed_roots(self):
        for entries in [
            [("package/../outside", tarfile.REGTYPE)],
            [("/package/outside", tarfile.REGTYPE)],
            [("package/a\\b", tarfile.REGTYPE)],
            [("package/link", tarfile.SYMTYPE)],
            [("package/link", tarfile.LNKTYPE)],
            [("package/index.js", tarfile.REGTYPE), ("other/index.js", tarfile.REGTYPE)],
        ]:
            with self.subTest(entries=entries):
                archive, destination = self.archive(entries)
                with self.assertRaises(ValueError):
                    corpus.extract_archive(archive, destination)

    def test_historical_archive_checks_identity_and_extracts_only_the_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "sample.zip"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("sample/package/package.json", json.dumps({"name": "sample", "version": "1"}))
                output.writestr("sample/package/index.js", "throw new Error('must never execute');")
                output.writestr("sample/research.json", "{}")
            package = {"name": "sample", "version": "1", "package_root": "sample/package/"}
            destination = root / "source"
            destination.mkdir()
            stats = historical.extract_archive(archive, destination, package)
            self.assertEqual(stats["files"], 2)
            self.assertFalse((destination / "research.json").exists())
            self.assertEqual((destination / "index.js").stat().st_mode & 0o111, 0)
            other = root / "other"
            other.mkdir()
            with self.assertRaisesRegex(ValueError, "identity"):
                historical.extract_archive(archive, other, {**package, "version": "2"})

    def test_historical_archive_rejects_an_absolute_path_after_prefix_removal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / "sample.zip"
            outside = root / "outside"
            with zipfile.ZipFile(archive, "w") as output:
                output.writestr("sample/package/package.json", '{"name":"sample","version":"1"}')
                output.writestr("sample/package/" + str(outside), "must stay inside the package")
            destination = root / "source"
            destination.mkdir()
            with self.assertRaises(ValueError):
                historical.extract_archive(archive, destination, {
                    "name": "sample", "version": "1", "package_root": "sample/package/"})
            self.assertFalse(outside.exists())

    def test_historical_archive_rejects_traversal_links_and_duplicate_files(self):
        for path, mode in [("sample/package/../escape", 0o100644),
                           ("sample/package/link", 0o120777),
                           ("sample/package/a\\b", 0o100644),
                           ("sample/package/package.json", 0o100644)]:
            with self.subTest(path=path), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                archive = root / "sample.zip"
                with zipfile.ZipFile(archive, "w") as output:
                    output.writestr("sample/package/package.json", '{"name":"sample","version":"1"}')
                    info = zipfile.ZipInfo(path)
                    info.external_attr = mode << 16
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        output.writestr(info, "data")
                destination = root / "source"
                destination.mkdir()
                with self.assertRaises(ValueError):
                    historical.extract_archive(archive, destination, {
                        "name": "sample", "version": "1", "package_root": "sample/package/"})


if __name__ == "__main__":
    unittest.main()
