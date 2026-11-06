"""Write the tag a run deployed back into the pins that name it.

A stack file says ``image: zot.safehomelan.com/ingest:${IMAGE_TAG:-build-182}``.
ship.yml exports ``IMAGE_TAG=build-256`` for the apps it built and pushed, so
*that deploy* is right. The pin underneath is not, and the fallback is what any
later deploy uses - a stack file edited for a port, a job that only touches
``deploy/stacks/``, the next person who runs ``docker stack deploy`` by hand.
The pin lagging the image is how ``ingest`` came to run build-182 while its
file said build-120: one unrelated deploy from being rolled back 62 builds.

PRs cannot fix this on their own. A build tag exists only after the build, so
the pin can only be written after the deploy - which is why the two repositories
never kept up. One repository can: the run that knows the tag writes it down,
and the next change carries it to main.

    python3 deploy/tools/pin_build_tag.py build-256 ingest status

Both places are updated together, because a pin is written twice: the stack
file that is deployed, and wizard.yaml's record of it. They drifted apart once
already (``status`` said build-150 and build-128) and nothing noticed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]      # deploy/

IMAGE_TAG = r'\$\{IMAGE_TAG:-([^}]*)\}'


def _stack_pins(text: str, app: str, tag: str) -> tuple[str, int]:
    """Point every ``/<app>:${IMAGE_TAG:-...}`` in a stack file at ``tag``."""
    pattern = re.compile(r'(?P<prefix>[^\s:]*/' + re.escape(app) + r':\$\{IMAGE_TAG:-)(?P<pin>[^}]*)(?P<close>\})')

    def swap(match: re.Match) -> str:
        return f'{match.group("prefix")}{tag}{match.group("close")}'

    return pattern.subn(swap, text)


def _wizard_pin(text: str, app: str, tag: str) -> tuple[str, int]:
    """The same pin in wizard.yaml: the version, and the image if it has one.

    Line-based on purpose. Rewriting the file through a YAML dumper would
    reformat every service in it, and the diff would bury the one line that
    changed.

    Keyed on the entry, not on the image line: ``homelab-wizard`` carries a
    ``version`` and no ``image`` at all, and a version that disagrees with the
    stack file is exactly the drift this is here to stop.
    """
    lines = text.splitlines()
    changed = 0
    start = 0
    while start < len(lines):
        head = re.match(r'^-\s+name:\s*(\S+)\s*$', lines[start])
        if not head or head.group(1) != app:
            start += 1
            continue
        end = start + 1
        while end < len(lines) and not re.match(r'^-\s+name:', lines[end]):
            end += 1
        for index in range(start + 1, end):
            version = re.match(r'^(\s*version:\s*)(.*)$', lines[index])
            if version and version.group(2).strip() != tag:
                lines[index] = f'{version.group(1)}{tag}'
                changed += 1
                continue
            image = re.match(
                r'^(\s*image:\s*\S*/' + re.escape(app) + r':\$\{IMAGE_TAG:-)([^}]*)(\})',
                lines[index])
            if image and image.group(2) != tag:
                lines[index] = f'{image.group(1)}{tag}{image.group(3)}'
                changed += 1
        start = end
    return ('\n'.join(lines) + ('\n' if text.endswith('\n') else ''), changed)


def pin(tag: str, apps: list[str], root: Path | None = None) -> list[str]:
    """Rewrite the pins for ``apps`` to ``tag``. Returns the files that moved."""
    root = Path(root or ROOT)
    if not tag:
        return []
    touched: list[str] = []

    for path in sorted((root / 'stacks').glob('*/stack.yml')):
        text = path.read_text()
        out, count = text, 0
        for app in apps:
            out, n = _stack_pins(out, app, tag)
            count += n
        if count and out != text:
            path.write_text(out)
            touched.append(f'stacks/{path.parent.name}/stack.yml')

    wizard = root / 'wizard.yaml'
    if wizard.is_file():
        text = wizard.read_text()
        out, count = text, 0
        for app in apps:
            out, n = _wizard_pin(out, app, tag)
            count += n
        if count and out != text:
            wizard.write_text(out)
            touched.append('wizard.yaml')

    return touched


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__.strip().splitlines()[0])
        print('usage: pin_build_tag.py <tag> <app> [<app>...]')
        return 2
    tag, apps = argv[1], argv[2:]
    touched = pin(tag, apps)
    if not touched:
        print(f'nothing to pin for {", ".join(apps)} at {tag}')
        return 0
    print(f'pinned {", ".join(apps)} at {tag}:')
    for name in touched:
        print(f'  {name}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
