#!/usr/bin/env python3
"""Decide where the full CI tier runs, and record what it found.

The Windows filesystem gates and the macOS workspace tests take most of a
run's runner time. A stack's top branch holds every commit of the members
below it, so the tier runs on that branch alone and its result stands for
them too:

  plan     says whether a pull request's head is one the tier runs on
  report   sets the `Full CI` commit status on the head that was tested and,
           when it passed, on each stack member that head contains
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

CONTEXT = 'Full CI'
LABEL = 'full-ci'
REMOTE = 'refs/remotes/origin/'
# GitHub rejects a longer status description.
DESCRIPTION_LIMIT = 140


def git(root, *arguments):
    return subprocess.run(
        ['git', '-C', root, *arguments], check=True, stdout=subprocess.PIPE, text=True).stdout


def branches_above(root, head_sha, head_ref):
    """The other branches whose history holds `head_sha` below their own head."""
    git(root, 'fetch', '--quiet', '--no-tags', '--filter=tree:0', 'origin',
        f'+refs/heads/*:{REMOTE}*')
    listed = git(root, 'for-each-ref', '--contains', head_sha,
                 '--format=%(objectname) %(refname)', REMOTE)
    above = []
    for line in listed.splitlines():
        sha, _, ref = line.partition(' ')
        name = ref.removeprefix(REMOTE)
        if sha != head_sha and name != head_ref and not name.startswith('gh-readonly-queue/'):
            above.append(name)
    return sorted(above)


def plan(event, labeled, above):
    """Whether the tier runs on this head, and the reason to print."""
    if event != 'pull_request':
        return True, 'Started by hand, so the full tier runs on this branch.'
    if labeled:
        return True, f'The pull request has the {LABEL} label, so the full tier runs on it.'
    if above:
        return False, (
            'The full tier runs on the top of this stack, which holds this head: '
            + ', '.join(above) + f'. Add the {LABEL} label to run it here too.')
    return True, 'No other branch builds on this head, so the full tier runs on it.'


def unmet(needs):
    """The jobs that did not succeed."""
    return [name for name in sorted(needs) if (needs[name] or {}).get('result') != 'success']


def open_pull(api, owner, ref):
    """The open pull request whose head is this repository's branch `ref`."""
    query = urllib.parse.urlencode({'state': 'open', 'head': f'{owner}:{ref}', 'per_page': 100})
    return next((pull for pull in api('GET', f'pulls?{query}') if pull['head']['ref'] == ref), None)


def covered(api, owner, head_ref, head_sha):
    """The open pull request for `head_ref`, and the stack members below it whose
    heads `head_sha` contains, nearest first."""
    tested = open_pull(api, owner, head_ref)
    members = []
    seen = {head_ref}
    pull = tested
    while pull and pull['base']['ref'] not in seen:
        seen.add(pull['base']['ref'])
        below = open_pull(api, owner, pull['base']['ref'])
        if below is None:
            break
        # A member pushed since the tested head was built has commits that
        # head lacks, so the result says nothing about it or what is under it.
        if api('GET', f'compare/{below["head"]["sha"]}...{head_sha}')['behind_by'] != 0:
            break
        members.append(below)
        pull = below
    return tested, members


def statuses(api, owner, needs, head_ref, head_sha):
    """The (sha, state, description) of every status this run sets."""
    failed = unmet(needs)
    if failed:
        return [(head_sha, 'failure', 'Did not pass: ' + ', '.join(failed))]
    tested, members = covered(api, owner, head_ref, head_sha)
    passed = 'The Windows filesystem gates and the macOS workspace tests passed'
    source = f'#{tested["number"]}' if tested else head_ref
    return [(head_sha, 'success', passed)] + [
        (member['head']['sha'], 'success', f'{passed} on {source}, which contains this head')
        for member in members]


def github(repository, token, base):
    def api(method, path, body=None):
        request = urllib.request.Request(
            f'{base}/repos/{repository}/{path}', method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={
                'Accept': 'application/vnd.github+json',
                'Authorization': f'Bearer {token}',
                'X-GitHub-Api-Version': '2022-11-28',
            })
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise SystemExit(f'{method} {path} failed: {error.code} {error.read().decode(errors="replace")}')
    return api


def run_plan(arguments):
    above = []
    if arguments.event == 'pull_request' and not arguments.labeled:
        above = branches_above(arguments.root, arguments.head_sha, arguments.head_ref)
    wanted, reason = plan(arguments.event, arguments.labeled, above)
    print(reason)
    if arguments.github_output:
        with open(arguments.github_output, 'a') as output:
            output.write(f'run={"true" if wanted else "false"}\n')
    return 0


def run_report(arguments):
    repository = os.environ['GITHUB_REPOSITORY']
    api = github(repository, os.environ['GITHUB_TOKEN'], os.environ.get('GITHUB_API_URL', 'https://api.github.com'))
    needs = json.loads(os.environ['NEEDS'])
    for sha, state, description in statuses(
            api, repository.split('/')[0], needs, arguments.head_ref, arguments.head_sha):
        api('POST', f'statuses/{sha}', {
            'context': CONTEXT,
            'state': state,
            'description': description[:DESCRIPTION_LIMIT],
            'target_url': arguments.run_url,
        })
        print(f'{sha} {state}: {description}')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest='command', required=True)

    planning = commands.add_parser('plan')
    planning.add_argument('--event', required=True)
    planning.add_argument('--head-sha', required=True)
    planning.add_argument('--head-ref', required=True)
    planning.add_argument('--labeled', action='store_true')
    planning.add_argument('--root', default='.')
    planning.add_argument('--github-output')
    planning.set_defaults(run=run_plan)

    reporting = commands.add_parser('report')
    reporting.add_argument('--head-sha', required=True)
    reporting.add_argument('--head-ref', required=True)
    reporting.add_argument('--run-url', required=True)
    reporting.set_defaults(run=run_report)

    arguments = parser.parse_args()
    return arguments.run(arguments)


if __name__ == '__main__':
    sys.exit(main())
