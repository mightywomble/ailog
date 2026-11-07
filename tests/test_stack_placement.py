"""Where a task lands is a decision, not an accident.

Swarm places a task once, on the node that is Ready when the service is
created, and never moves it again. After the November Proxmox reboot the
manager booted first, so it took 22 of 28 services and all four databases while
four workers sat idle - and it would still be like that. Every stack therefore
states its placement: a pool label pin, an explicit hostname (ailog's SQLite
WAL cannot be read from two nodes), a spread preference for multi-replica
services, or `mode: global` where one-per-node is the definition.
"""

from __future__ import annotations

from pathlib import Path

STACKS = Path(__file__).resolve().parents[1] / 'deploy' / 'stacks'


def _files():
    return sorted(STACKS.glob('*/stack.yml'))


def test_every_stack_says_where_its_tasks_may_land():
    loose = [p.parent.name for p in _files()
             if not any(marker in p.read_text()
                        for marker in ('node.labels.pool', 'node.hostname ==', 'mode: global'))]
    assert loose == [], f'no placement on: {loose} - it will land wherever boot order puts it'


def test_the_pools_are_referenced_and_none_is_unknown():
    pools = set()
    for p in _files():
        for line in p.read_text().splitlines():
            if 'node.labels.pool ==' in line:
                pools.add(line.split('==')[-1].strip())
    assert pools <= {'w1', 'w2', 'w3', 'w4'}, pools
    # all four workers carry work; capacity left on the bench is capacity wasted
    assert pools == {'w1', 'w2', 'w3', 'w4'}


def test_the_manager_is_not_a_pool_member():
    text = ' '.join(p.read_text() for p in _files())
    assert 'node.labels.pool == mgr' not in text
    assert 'node.labels.pool != mgr' in text   # multi-replica services exclude it


def test_the_stateful_pairs_are_not_split_across_nodes():
    """A database and the app that hammers it belong on the same machine."""
    for stack in ('vikunja', 'wordpress', 'metamcp'):
        text = (STACKS / stack / 'stack.yml').read_text()
        pins = {line.split('==')[-1].strip()
                for line in text.splitlines() if 'node.labels.pool ==' in line}
        assert len(pins) == 1, f'{stack} splits its services across {pins}'


def test_ailog_stays_pinned_by_hostname():
    """SQLite on NFS: two nodes on one WAL is a corrupt database waiting."""
    text = (STACKS / 'ailog' / 'stack.yml').read_text()
    assert 'node.hostname == swarm-worker4' in text
    assert 'node.labels.pool' not in text
