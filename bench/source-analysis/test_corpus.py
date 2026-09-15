import base64
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("corpus", Path(__file__).with_name("corpus.py"))
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)

spec = importlib.util.spec_from_file_location("runner", Path(__file__).with_name("run.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

spec = importlib.util.spec_from_file_location("comparison", Path(__file__).with_name("compare.py"))
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


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


if __name__ == "__main__":
    unittest.main()
