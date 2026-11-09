"""Standalone docker hosts, read as compose projects instead of a flat list.

The swarm half of the Docker page is covered elsewhere. This file pins the half
that did not exist: a host with no swarm services used to render "No containers
are grouped into apps on this host", because the grouping only ever came from
swarm stacks. A compose project label was already on every container; it just
was not carried out of the update scan, so the page could not group by it.

Four things have to stay true for this to keep working:

* the compose project survives the update scan (``compose_project_of``,
  ``updates_for``),
* the grouping keeps loose containers visible rather than dropping them,
* the API is a second view of one scan, not a second scan,
* the page reads versions, because a list of projects that does not say whether
  any of them is behind is just a prettier ``docker ps``.
"""

import os

from dockermon import updates

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(ROOT, *parts), 'r', encoding='utf-8') as handle:
        return handle.read()


def _docker_template():
    return _read('templates', 'docker.html')


# --------------------------------------------------------------------------
# the label, out of the container
# --------------------------------------------------------------------------

def test_a_compose_service_reports_its_project():
    container = {'labels': {'com.docker.compose.project': 'managelm',
                            'com.docker.compose.service': 'portal'}}
    assert updates.compose_project_of(container) == 'managelm'


def test_a_container_without_a_project_reports_nothing():
    assert updates.compose_project_of({'labels': {}}) == ''
    assert updates.compose_project_of({}) == ''
    assert updates.compose_project_of({'labels': None}) == ''


def test_the_api_shape_of_labels_is_understood_too():
    """The endpoint serialises labels as pairs; the collector builds a dict.

    Both reach this helper depending on whether the caller came through a live
    snapshot or a cached payload, and silently returning '' for one of them
    would empty the page after a restart.
    """
    container = {'labels': [['com.docker.compose.project', 'gitea']]}
    assert updates.compose_project_of(container) == 'gitea'


def test_a_project_owned_container_is_not_a_self_managed_one():
    """The two helpers answer different questions and must not be merged.

    ``owner_project`` exists to *exclude* Nextcloud AIO's containers from the
    update list. Reusing it here would make every normal compose service look
    ungrouped, which is the opposite of this view's job.
    """
    container = {'labels': {'com.docker.compose.project': 'immich',
                            'com.docker.compose.service': 'immich-server'}}
    assert updates.owner_project(container) == ''
    assert updates.compose_project_of(container) == 'immich'


# --------------------------------------------------------------------------
# the grouping
# --------------------------------------------------------------------------

def _result(*rows):
    return {'host_key': 'db-16', 'containers': list(rows), 'ts': 1.0}


def _row(name, project=None, update=False, tag='latest', service=None):
    row = {'name': name, 'image': f'example/{name}:{tag}', 'tag': tag,
           'state': 'running', 'cpu_percent': 1.0, 'mem_used': 1024,
           'update_available': update, 'local_digest': 'a' * 12,
           'remote_digest': 'b' * 12 if update else 'a' * 12}
    if project:
        row['project'] = project
    if service:
        row['service'] = service
    return row


def test_containers_are_folded_into_their_projects():
    grouped = updates.group_by_project(_result(
        _row('managelm-portal-1', 'managelm', update=True, service='portal'),
        _row('managelm-postgres-1', 'managelm', service='postgres'),
        _row('gitea', 'gitea'),
    ))
    names = [p['name'] for p in grouped['projects']]
    assert names == ['gitea', 'managelm']
    managelm = grouped['projects'][1]
    assert managelm['count'] == 2
    assert managelm['updates'] == 1
    assert managelm['update_available'] is True
    assert [c['name'] for c in managelm['containers']] == ['managelm-portal-1', 'managelm-postgres-1']


def test_a_project_with_nothing_to_do_says_so():
    grouped = updates.group_by_project(_result(_row('gitea', 'gitea')))
    project = grouped['projects'][0]
    assert project['update_available'] is False
    assert project['updates'] == 0


def test_loose_containers_are_kept_not_dropped():
    """The portainer agent has no compose project and must still be visible.

    A page that says a host runs three projects when it also runs two unmanaged
    containers is wrong by omission, and those are the containers nothing will
    ever update for you.
    """
    grouped = updates.group_by_project(_result(
        _row('gitea', 'gitea'),
        _row('portainer_agent'),
    ))
    assert len(grouped['projects']) == 1
    assert [c['name'] for c in grouped['loose']] == ['portainer_agent']


def test_the_grouping_does_not_mutate_the_scan_it_was_given():
    rows = [_row('gitea', 'gitea')]
    result = _result(*rows)
    updates.group_by_project(result)
    assert result['containers'][0]['project'] == 'gitea'


def test_the_tags_a_project_pins_are_summarised():
    grouped = updates.group_by_project(_result(
        _row('a', 'immich', tag='v3.3.6'),
        _row('b', 'immich', tag='v3.3.6'),
    ))
    assert grouped['projects'][0]['tags'] == ['v3.3.6']


def test_an_image_pinned_by_id_does_not_pollute_the_version_list():
    """managelm's postgres and redis are pinned by image ID, not by tag.

    `docker ps` then reports a 64-character digest where a version would be, and
    putting that in a project's subtitle reads as corruption. It is counted
    separately instead.
    """
    image_id = '1fb72075a1de85a1d39de23c2da81baef1b71bf5c0b61a14cbbfdb072a6246d9'
    grouped = updates.group_by_project(_result(
        _row('managelm-portal-1', 'managelm', tag='latest'),
        _row('managelm-postgres-1', 'managelm', tag=image_id),
    ))
    project = grouped['projects'][0]
    assert project['tags'] == ['latest']
    assert project['by_image_id'] == 1


# --------------------------------------------------------------------------
# the API
# --------------------------------------------------------------------------

def test_the_compose_endpoint_reads_the_cached_scan_instead_of_scanning_again():
    """Re-walking the host would double the SSH work to answer nothing new."""
    routes = _read('dockermon', 'routes.py')
    block = routes[routes.index("def api_compose_updates"):]
    block = block[:block.index('@docker_bp.route')]
    assert 'dupdates.state(host_key)' in block
    assert 'refresh' in block
    # and it must not queue a background scan of its own
    assert 'scan_async' not in block


def test_the_compose_endpoint_is_read_only():
    routes = _read('dockermon', 'routes.py')
    line = [ln for ln in routes.splitlines() if '/compose-updates' in ln][0]
    assert 'methods' not in line


def test_the_route_exists_for_a_host_path():
    routes = _read('dockermon', 'routes.py')
    assert "@docker_bp.route('/api/docker/hosts/<path:host_key>/compose-updates')" in routes


# --------------------------------------------------------------------------
# the page
# --------------------------------------------------------------------------

def test_a_host_without_a_swarm_groups_by_compose_instead():
    template = _docker_template()
    render = template[template.index('function renderApps()'):]
    render = render[:render.index('function renderCluster')]
    assert 'renderComposeApps()' in render
    assert 'if (!view.swarm) return renderComposeApps();' in render


def test_the_page_shows_a_running_tag_and_the_digests():
    template = _docker_template()
    block = template[template.index('function composeVersions'):]
    block = block[:block.index('function renderComposeApps')]
    assert 'c.tag' in block
    assert 'c.local_digest' in block
    assert 'c.remote_digest' in block


def test_an_update_is_called_out_and_a_current_image_is_not():
    template = _docker_template()
    block = template[template.index('function composeVersions'):]
    block = block[:block.index('function renderComposeApps')]
    assert 'newer upstream' in block
    assert 'c.update_available' in block


def test_clicking_a_project_opens_its_containers():
    template = _docker_template()
    block = template[template.index('function renderComposeApps'):]
    block = block[:block.index('function appMatches')]
    assert 'appsOpen' in block
    assert 'data-app' in block
    assert 'apps-detail' in block


def test_the_compose_projects_are_fetched_when_the_apps_view_opens():
    template = _docker_template()
    assert "loadCompose().then(renderApps)" in template
    assert "'/compose-updates'" in template
