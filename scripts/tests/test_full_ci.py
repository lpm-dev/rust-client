import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import urllib.parse

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('full_ci', ROOT / 'scripts/ci/full-ci.py')
full_ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(full_ci)

PASSED = {name: {'result': 'success'} for name in (
    'plan', 'windows-filesystem', 'windows-filesystem-arm64', 'macos-workspace-tests')}


def git(directory, *arguments):
    environment = dict(os.environ, GIT_AUTHOR_NAME='t', GIT_AUTHOR_EMAIL='t@example.com',
                       GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.com')
    return subprocess.run(['git', '-C', str(directory), *arguments], check=True,
                          capture_output=True, text=True, env=environment).stdout.strip()


class Stack:
    """An origin with main <- bottom <- middle <- top, and a clone of it."""

    def __init__(self, directory):
        self.origin = Path(directory) / 'origin'
        self.origin.mkdir()
        git(self.origin, 'init', '--quiet', '--initial-branch=main')
        self.shas = {'main': self.commit('main')}
        for branch in ('bottom', 'middle', 'top'):
            git(self.origin, 'checkout', '--quiet', '-b', branch)
            self.shas[branch] = self.commit(branch)
        self.clone = Path(directory) / 'clone'
        git(directory, 'clone', '--quiet', '--branch', 'main', '--single-branch', str(self.origin), str(self.clone))
        git(self.clone, 'fetch', '--quiet', 'origin', self.shas['top'])

    def commit(self, message):
        git(self.origin, 'commit', '--quiet', '--allow-empty', '-m', message)
        return git(self.origin, 'rev-parse', 'HEAD')

    def branch(self, name, start):
        git(self.origin, 'branch', name, start)

    def above(self, branch):
        return full_ci.branches_above(str(self.clone), self.shas[branch], branch)


class BranchesAboveTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.stack = Stack(directory.name)

    def test_a_stack_member_lists_every_branch_built_on_it(self):
        self.assertEqual(self.stack.above('bottom'), ['middle', 'top'])
        self.assertEqual(self.stack.above('middle'), ['top'])

    def test_the_top_of_a_stack_has_nothing_above_it(self):
        self.assertEqual(self.stack.above('top'), [])

    def test_a_second_branch_at_the_same_commit_is_not_above_it(self):
        self.stack.branch('top-backup', 'top')
        self.assertEqual(self.stack.above('top'), [])

    def test_a_merge_queue_branch_is_not_above_the_head_it_merges(self):
        self.stack.branch('gh-readonly-queue/main/pr-7-abc', 'top')
        git(self.stack.origin, 'checkout', '--quiet', 'gh-readonly-queue/main/pr-7-abc')
        self.stack.commit('queued')
        self.assertEqual(self.stack.above('top'), [])

    def test_a_head_its_own_branch_has_moved_past_is_not_under_that_branch(self):
        git(self.stack.origin, 'checkout', '--quiet', 'top')
        self.stack.commit('newer')
        self.assertEqual(self.stack.above('top'), [])

    def test_a_branch_pushed_after_the_checkout_is_seen(self):
        git(self.stack.origin, 'checkout', '--quiet', '-b', 'later', 'top')
        self.stack.commit('later')
        self.assertEqual(self.stack.above('top'), ['later'])


class PlanTests(unittest.TestCase):
    def wanted(self, event, labeled=False, above=()):
        return full_ci.plan(event, labeled, list(above))[0]

    def test_the_top_of_a_stack_and_a_lone_pull_request_run_the_tier(self):
        self.assertTrue(self.wanted('pull_request'))

    def test_a_member_with_a_branch_above_it_leaves_the_tier_to_that_branch(self):
        wanted, reason = full_ci.plan('pull_request', False, ['codex/top'])
        self.assertFalse(wanted)
        self.assertIn('codex/top', reason)

    def test_the_label_runs_the_tier_on_a_member_below_the_top(self):
        self.assertTrue(self.wanted('pull_request', labeled=True, above=['codex/top']))

    def test_a_run_started_by_hand_always_runs_the_tier(self):
        self.assertTrue(self.wanted('workflow_dispatch', above=['codex/top']))

    def test_the_decision_reaches_the_workflow_as_an_output(self):
        with tempfile.TemporaryDirectory() as directory:
            stack = Stack(directory)
            output = Path(directory) / 'output'
            for branch, expected in (('middle', 'run=false\n'), ('top', 'run=true\n')):
                output.write_text('')
                with patch('sys.argv', ['full-ci', 'plan', '--event', 'pull_request',
                                        '--head-sha', stack.shas[branch], '--head-ref', branch,
                                        '--root', str(stack.clone), '--github-output', str(output)]), \
                        patch('builtins.print'):
                    self.assertEqual(full_ci.main(), 0)
                self.assertEqual(output.read_text(), expected)


class UnmetJobTests(unittest.TestCase):
    def test_every_job_succeeding_leaves_nothing_unmet(self):
        self.assertEqual(full_ci.unmet(PASSED), [])

    def test_a_failed_cancelled_or_skipped_job_is_unmet(self):
        for result in ('failure', 'cancelled', 'skipped'):
            needs = dict(PASSED, **{'macos-workspace-tests': {'result': result}})
            self.assertEqual(full_ci.unmet(needs), ['macos-workspace-tests'], result)


class Repository:
    """The pull requests and ancestry a fake API answers from."""

    def __init__(self, pulls, behind=()):
        self.pulls = pulls
        self.behind = set(behind)
        self.posted = []

    def api(self, method, path, body=None):
        if method == 'POST':
            self.posted.append((path, body))
            return {}
        if path.startswith('pulls?'):
            query = urllib.parse.parse_qs(path.partition('?')[2])
            owner, _, ref = query['head'][0].partition(':')
            assert owner == 'lpm-dev' and query['state'] == ['open']
            return [pull for pull in self.pulls if pull['head']['ref'] == ref]
        base, head = re.fullmatch(r'compare/(\w+)\.\.\.(\w+)', path).groups()
        return {'behind_by': 1 if base in self.behind else 0}


def pull(number, ref, base):
    return {'number': number, 'head': {'ref': ref, 'sha': f'sha{number}'}, 'base': {'ref': base}}


STACK = [pull(1, 'codex/bottom', 'main'), pull(2, 'codex/middle', 'codex/bottom'), pull(3, 'codex/top', 'codex/middle')]


class StatusTests(unittest.TestCase):
    def statuses(self, repository, needs=PASSED, ref='codex/top', sha='sha3'):
        return full_ci.statuses(repository.api, 'lpm-dev', needs, ref, sha)

    def test_a_passing_top_covers_every_member_below_it(self):
        statuses = self.statuses(Repository(STACK))
        self.assertEqual([(sha, state) for sha, state, _ in statuses],
                         [('sha3', 'success'), ('sha2', 'success'), ('sha1', 'success')])
        self.assertIn('#3', statuses[1][2])

    def test_a_failing_top_marks_only_the_head_that_was_tested(self):
        needs = dict(PASSED, **{'windows-filesystem-arm64': {'result': 'failure'}})
        self.assertEqual(self.statuses(Repository(STACK), needs),
                         [('sha3', 'failure', 'Did not pass: windows-filesystem-arm64')])

    def test_a_member_the_tested_head_lacks_is_not_covered_nor_anything_under_it(self):
        statuses = self.statuses(Repository(STACK, behind=['sha2']))
        self.assertEqual([sha for sha, _, _ in statuses], ['sha3'])

    def test_a_member_under_a_covered_one_stops_where_the_tested_head_lacks_it(self):
        statuses = self.statuses(Repository(STACK, behind=['sha1']))
        self.assertEqual([sha for sha, _, _ in statuses], ['sha3', 'sha2'])

    def test_a_lone_pull_request_marks_only_itself(self):
        statuses = self.statuses(Repository([pull(9, 'codex/alone', 'main')]), ref='codex/alone', sha='sha9')
        self.assertEqual([sha for sha, _, _ in statuses], ['sha9'])

    def test_a_branch_without_a_pull_request_marks_only_its_head(self):
        statuses = self.statuses(Repository(STACK), ref='codex/unsubmitted', sha='abc')
        self.assertEqual([sha for sha, _, _ in statuses], ['abc'])

    def test_pull_requests_that_name_each_other_as_base_end_the_walk(self):
        looped = [pull(1, 'codex/a', 'codex/b'), pull(2, 'codex/b', 'codex/a')]
        statuses = self.statuses(Repository(looped), ref='codex/a', sha='sha1')
        self.assertEqual([sha for sha, _, _ in statuses], ['sha1', 'sha2'])

    def test_the_report_posts_each_status_under_the_required_context(self):
        repository = Repository(STACK)
        environment = {'GITHUB_REPOSITORY': 'lpm-dev/rust-client', 'GITHUB_TOKEN': 't', 'NEEDS': json.dumps(PASSED)}
        with patch.dict(os.environ, environment), patch.object(full_ci, 'github', lambda *_: repository.api), \
                patch('sys.argv', ['full-ci', 'report', '--head-sha', 'sha3', '--head-ref', 'codex/top',
                                   '--run-url', 'https://example.com/run']), patch('builtins.print'):
            self.assertEqual(full_ci.main(), 0)
        self.assertEqual([path for path, _ in repository.posted],
                         ['statuses/sha3', 'statuses/sha2', 'statuses/sha1'])
        for _, body in repository.posted:
            self.assertEqual(body['context'], 'Full CI')
            self.assertEqual(body['state'], 'success')
            self.assertEqual(body['target_url'], 'https://example.com/run')
            self.assertLessEqual(len(body['description']), 140)


if __name__ == '__main__':
    unittest.main()
