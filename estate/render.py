"""Reading `wizard.yaml` and moving exactly one number inside the stack file.

Ported from the wizard's ``core.py`` (render_stack / bump_image / mirror_entry /
with_tag / image_ref) because that code is the estate's actual contract with
CI: `ship.yml` interpolates `${IMAGE_TAG:-<pin>}` out of these files, and a
re-render that dropped a hand-written comment has already caused one outage's
worth of confusion.

The one deliberate difference from the wizard: nothing here writes.  It returns
the new text so the caller can diff, show and commit it.
"""

from __future__ import annotations

import re

import yaml

HEADER = """# {name} - rendered from wizard.yaml by homelab-wizard.
# Owned by the wizard: image tag, published ports, replicas, volumes.
# Everything else here is hand-maintained and survives a re-render.
"""

# build-kind stacks carry the tag CI just produced and fall back to the pin.
TAG_PLACEHOLDER = '${IMAGE_TAG:-%s}'


def service_of(entry: dict) -> str:
    return entry.get('service') or entry['name']


def image_ref(entry: dict, registry: str = 'zot.safehomelan.com') -> str:
    """The image line this entry implies - the same rule `ship.yml` assumes.

    ``release: manual`` exists for one real case: a build-kind app that is pushed
    under a human version tag by hand, in a stack that also carries another
    build app.  `ship.yml` exports one IMAGE_TAG per *stack*, so a stack with two
    `${IMAGE_TAG:-...}` images can only be deployed when CI built both - it
    checks every image in the file and refuses the whole stack otherwise.  Such an
    app keeps a literal pin, and the estate is told not to pretend otherwise.
    """
    repo = entry.get('repo') or entry['name']
    version = str(entry.get('version') or 'latest')
    ref = f'{registry}/{repo}'
    if entry.get('kind') == 'build' and entry.get('release') != 'manual':
        return ref + ':' + TAG_PLACEHOLDER % version
    return f'{ref}:{version}'


def with_tag(source: str, version: str) -> str:
    """'ghcr.io/acme/app:1.2.3' + '1.2.4' -> 'ghcr.io/acme/app:1.2.4'.

    mirror-images.json is keyed on the source reference, so a version bump that
    left the source tag alone looks like "nothing changed" to mirror.yml and the
    new image is never copied into zot.
    """
    ref = (source or '').strip()
    if not ref or not version or '@' in ref:
        return ref
    head, sep, last = ref.rpartition('/')
    if ':' in last:
        last = last.split(':', 1)[0]
    return f'{head}{sep}{last}:{version}'


def mirror_entry(entry: dict) -> dict | None:
    if entry.get('kind') != 'mirror' or not entry.get('source'):
        return None
    return {'name': entry.get('repo') or entry['name'],
            'source': with_tag(entry.get('source'), entry.get('version'))}


def bump_image(text: str, service: str, image: str) -> tuple[str, bool]:
    """Rewrite one service's `image:` line and nothing else.

    A full re-render goes through ``yaml.safe_dump``, which deletes every
    comment - and those comments are the swarm reasoning (why guacd joins the
    overlay, why env_file is inline) that was expensive to establish.  A version
    bump only needs one line to move.
    """
    lines = text.splitlines(keepends=True)
    head = None
    indent = 0
    for i, line in enumerate(lines):
        m = re.match(r'^(\s*)([A-Za-z0-9._-]+):\s*(#.*)?$', line)
        if m and m.group(2) == service and (head is None or len(m.group(1)) <= indent):
            head, indent = i, len(m.group(1))
            continue
        if head is not None:
            stripped = line.strip()
            if stripped and not stripped.startswith('#') and (len(line) - len(line.lstrip())) <= indent:
                break
            m2 = re.match(r'^(\s*)image:\s*(.+?)\s*$', line)
            if m2:
                quote = '"' if m2.group(2)[:1] == '"' else ''
                lines[i] = f'{m2.group(1)}image: {quote}{image}{quote}\n'
                return ''.join(lines), True
    return text, False


def validate(entry: dict) -> list[str]:
    """The rules the wizard enforces, kept so a bad edit cannot reach CI."""
    problems = []
    name = entry.get('name') or ''
    if not re.match(r'^[a-z0-9][a-z0-9-]{1,30}$', name):
        problems.append('name must be lowercase alphanumeric/hyphen (2-31 chars)')
    if entry.get('kind') not in ('build', 'mirror', 'image'):
        problems.append('kind must be build, mirror or image')
    if entry.get('kind') == 'mirror' and not entry.get('source'):
        problems.append('mirror services need an upstream source (registry/repo:tag)')
    return problems


# --------------------------------------------------------------------------
# the document itself
# --------------------------------------------------------------------------

def load_intent(text: str) -> dict:
    return yaml.safe_load(text) or {}


def dump_intent(doc: dict, header: str = '') -> str:
    return header + yaml.safe_dump(doc, sort_keys=False, width=100)


def header_of(text: str) -> str:
    """Everything above `version:` - the intent file's hand-written preamble.

    `wizard.yaml` starts with a comment block explaining the three kinds; a
    rewrite that dropped it would remove the only explanation a reader gets.
    """
    if not text:
        return ''
    marker = '\nversion:'
    if marker in text:
        return text.split(marker, 1)[0] + '\n'
    return ''


def find_service(doc: dict, name: str) -> dict | None:
    return next((s for s in (doc.get('services') or []) if s.get('name') == name), None)


def bump_intent(text: str, name: str, version: str) -> tuple[str, dict]:
    """Set one service's version (and, for a mirror, its source tag).

    Returns the new document text and the entry as it now stands, because the
    caller needs the entry to render the image line and the mirror record.
    """
    doc = load_intent(text)
    entry = find_service(doc, name)
    if entry is None:
        raise KeyError(f'{name} is not in wizard.yaml')
    entry['version'] = version
    if entry.get('kind') == 'mirror':
        entry['source'] = with_tag(entry.get('source'), version)
    return dump_intent(doc, header_of(text)), entry


def drift(entry: dict, stack_text: str) -> str:
    """The image the intent implies vs the image the stack actually deploys.

    Empty when they agree.  A non-empty answer is the thing the estate view
    exists to show: `wizard.yaml` says 1.19.0 and the stack runs 1.18.0.
    """
    want = image_ref(entry)
    try:
        doc = yaml.safe_load(stack_text) or {}
    except yaml.YAMLError:
        return 'stack file is not valid yaml'
    service = (doc.get('services') or {}).get(service_of(entry)) or {}
    have = str(service.get('image') or '')
    return '' if have == want else f'{have} (intent: {want})'
