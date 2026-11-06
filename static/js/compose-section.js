// Settings -> Docker: the compose projects on hosts that are not swarm nodes.
//
// Read-only on purpose. The deploy is a commit: the project's compose.yml lives
// in deploy/compose/<name>/ and .gitea/workflows/compose.yml ships it. A button
// here that ran docker on a host would be a second, unaudited path to the same
// machine - and the last time this estate had two writers, a service ran eight
// releases behind its own pin.
//
// So this section answers the questions the tree can answer: what exists, where
// it runs, what it pins, which images come from zot, and what is wrong with the
// entry itself.

const esc = (value) => String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');

let loaded = false;

function chip(text, tone) {
    const tones = {
        ok: 'bg-emerald-500/15 text-emerald-300',
        warn: 'bg-amber-500/15 text-amber-300',
        bad: 'bg-rose-500/15 text-rose-300',
        quiet: 'bg-white/10 text-slate-300',
    };
    return `<span class="px-2 py-0.5 rounded text-xs ${tones[tone] || tones.quiet}">${esc(text)}</span>`;
}

function projectCard(project) {
    if (project.error) {
        return `<div class="bg-white/5 rounded-lg p-4">
            ${chip('broken', 'bad')} <span class="font-medium">${esc(project.name)}</span>
            <p class="text-sm text-rose-300 mt-2">${esc(project.error)}</p>
        </div>`;
    }

    const images = (project.images || []).map((image) => `
        <tr class="border-b border-white/5 last:border-0">
            <td class="py-1 pr-3 text-xs text-slate-300">${esc(image.image)}</td>
            <td class="py-1 pr-3 text-xs font-mono">${esc(image.pin)}</td>
            <td class="py-1 text-xs">${image.from_zot
                ? chip('zot', 'ok')
                : chip('upstream', 'warn')}</td>
        </tr>`).join('');

    const problems = (project.problems || []).length
        ? `<ul class="mt-2 space-y-1 text-sm text-amber-300">
             ${project.problems.map((p) => `<li>${esc(p)}</li>`).join('')}
           </ul>`
        : '';

    return `<div class="bg-white/5 rounded-lg p-4" data-compose-project="${esc(project.name)}">
        <div class="flex items-start justify-between gap-3">
            <div>
                <div class="font-medium">${esc(project.name)}</div>
                <div class="text-xs text-slate-400 mt-0.5">${esc(project.description || '')}</div>
            </div>
            <div class="text-right text-xs text-slate-400">
                <div>${esc(project.host)}</div>
                <div class="font-mono">${esc(project.dir)}</div>
            </div>
        </div>
        <table class="w-full mt-3"><tbody>${images}</tbody></table>
        <div class="mt-2 text-xs text-slate-400">
            .env keys: ${(project.env_keys || []).map((k) => `<code class="mr-1">${esc(k)}</code>`).join('')}
            <span class="ml-1">(values stay on the host, in <code>${esc(project.dir)}/${esc(project.env_file)}</code>)</span>
        </div>
        ${problems}
    </div>`;
}

async function load() {
    const mount = document.getElementById('docker-compose-projects');
    if (!mount) return;
    if (!loaded) mount.innerHTML = '<p class="text-sm text-slate-400">Reading the estate…</p>';
    try {
        const response = await fetch('/api/compose/projects', { headers: { Accept: 'application/json' } });
        const data = await response.json();
        const head = data.head ? data.head.slice(0, 8) : '';
        const projects = data.projects || [];

        mount.innerHTML = data.error
            ? `<p class="text-sm text-rose-300">${esc(data.error)}</p>`
            : (projects.length
                ? projects.map(projectCard).join('')
                : '<p class="text-sm text-slate-400">No compose projects yet. A project is a directory: '
                  + '<code>deploy/compose/&lt;name&gt;/{{compose.yml, project.json, .env.example}}</code>.</p>');

        const foot = document.getElementById('docker-compose-head');
        if (foot) foot.textContent = head ? `deployed tree ${head}` : '';
        loaded = true;
    } catch (error) {
        mount.innerHTML = `<p class="text-sm text-rose-300">Could not read the projects: ${esc(error.message)}</p>`;
    }
}

// The settings modal switches sections itself; this only has to notice that its
// own section became visible, and only fetch once.
document.addEventListener('click', (event) => {
    const button = event.target.closest('.settings-nav-btn');
    if (button && button.dataset.section === 'docker-compose') load();
});

export { load as loadComposeProjects };
