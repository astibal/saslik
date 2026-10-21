function skewerStoreFamily(store) {
    if (store.system) return 'System';
    const text = `${store.snap_name || ''} ${store.label || ''} ${store.path || ''}`.toLowerCase();
    if (text.includes('firefox')) return 'Firefox';
    if (text.includes('thunderbird')) return 'Thunderbird';
    if (text.includes('librewolf')) return 'LibreWolf';
    if (text.includes('brave')) return 'Brave';
    if (/chrom|chrome|vivaldi|edge/.test(text)) return 'Chromium';
    return 'NSS';
}

function skewerStoreVariant(store) {
    if (store.system) return 'Ubuntu';
    if (store.snap_name) {
        if (store.snap_lifecycle === 'common') return 'common · sdílený store';
        const state = store.snap_lifecycle === 'current' ? 'current'
            : store.snap_lifecycle === 'retained' ? 'retained' : 'neznámá revize';
        return `${state}${store.snap_revision ? ` · ${store.snap_revision}` : ''}`;
    }
    const label = store.label || store.path || 'NSS profil';
    return label.length > 42 ? `…${label.slice(-41)}` : label;
}

async function refreshSkewerReports() {
    try {
        const response = await fetch('/api/skewer/reports', {cache: 'no-store'});
        if (!response.ok) return;
        const reports = (await response.json()).reports || [];
        const signature = JSON.stringify(reports.map(({received_at, ...stable}) => stable));
        if (signature === skewerReportsSignature) return;
        skewerReportsSignature = signature;
        const section = $('skewer-trust');
        const devel = document.body.classList.contains('devel-mode');
        section.classList.toggle('hidden', !reports.length && !devel);
        if (!reports.length && !devel) {
            selectedSkewerHost = '';
            return;
        }
        if (!reports.length) selectedSkewerHost = '__local__';
        else if (selectedSkewerHost !== '__local__' && !reports.some(report => report.hostname === selectedSkewerHost))
            selectedSkewerHost = reports[0].hostname;

        const tabs = $('skewer-trust-tabs');
        tabs.classList.toggle('hidden', reports.length === 1 && !devel);
        tabs.innerHTML = reports.map(report =>
            `<button type="button" data-skewer-host="${esc(report.hostname)}" class="${report.hostname === selectedSkewerHost ? 'active' : ''}"><i class="${report.online ? 'online' : 'offline'}"></i>${esc(report.hostname)}</button>`
        ).join('') + (devel ? `<button type="button" data-ca-local class="dev-system-tab ${selectedSkewerHost === '__local__' ? 'active' : ''}">DEV / SYS</button>` : '');
        tabs.querySelectorAll('[data-skewer-host]').forEach(button => button.onclick = () => {
            selectedSkewerHost = button.dataset.skewerHost;
            skewerReportsSignature = '';
            refreshSkewerReports();
        });
        tabs.querySelector('[data-ca-local]')?.addEventListener('click', () => {
            selectedSkewerHost = '__local__';
            skewerReportsSignature = '';
            refreshSkewerReports();
        });
        const localSelected = selectedSkewerHost === '__local__';
        $('skewer-trust-content').classList.toggle('hidden', localSelected);
        $('local-ca-panel').classList.toggle('hidden', !localSelected);
        if (localSelected) return;

        const report = reports.find(item => item.hostname === selectedSkewerHost) || reports[0];
        const families = new Map();
        const applications = new Map((report.ca?.applications || [])
            .map(application => [application.id, application]));
        const icons = {Firefox: 'icons/firefox.svg', Chromium: 'icons/chromium.png',
            LibreWolf: 'icons/librewolf.svg', Brave: 'icons/brave.svg',
            Thunderbird: 'icons/thunderbird.svg', System: 'icons/system.svg',
            NSS: 'icons/system.svg'};
        for (const store of report.ca?.stores || []) {
            const fallback = skewerStoreFamily(store);
            const application = applications.get(store.application_id) ||
                {id: store.application_id || `fallback:${fallback}`, alias: fallback, icon: ''};
            if (!families.has(application.id)) families.set(application.id, {application, stores: []});
            families.get(application.id).stores.push(store);
        }
        const updated = report.received_at
            ? new Date(report.received_at * 1000).toLocaleString() : '—';
        const groupState = group => {
            const active = group.stores.filter(store => store.snap_lifecycle !== 'retained');
            const trusted = active.filter(store => store.installed).length;
            return active.length && trusted === active.length ? 'trusted'
                : trusted > 0 ? 'partial' : 'unconfigured';
        };
        const orderedFamilies = [...families].sort(([, left], [, right]) => {
            const priority = group => groupState(group) === 'trusted' ? 0
                : group.application.recognized ? 1 : 2;
            return priority(left) - priority(right)
                || String(left.application.alias).localeCompare(String(right.application.alias));
        });
        const compact = orderedFamilies.map(([, group]) => {
            const {application, stores} = group;
            const activeStores = stores.filter(store => store.snap_lifecycle !== 'retained');
            const trusted = activeStores.filter(store => store.installed).length;
            const fallback = skewerStoreFamily(stores[0] || {});
            const reportedIcon = /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(application.icon || '')
                ? application.icon : '';
            // Skewer owns desktop discovery and reports the exact application
            // icon. Local family artwork only covers old/incomplete reports.
            const icon = reportedIcon || icons[fallback] || icons.NSS;
            const versions = activeStores.filter(store => store.snap_name).map(store =>
                store.snap_lifecycle === 'common' ? 'common'
                    : store.snap_lifecycle === 'current' ? `current ${store.snap_revision}` : 'unknown'
            ).filter((value, index, values) => values.indexOf(value) === index);
            const state = groupState(group);
            const ratio = `${trusted}/${activeStores.length}`;
            const title = `${application.alias || fallback}: ${ratio} aktivní důvěryhodné`;
            return `<span class="ca-app-compact ${state}" title="${esc(title)}"><img src="${esc(icon)}" alt=""><i></i><span><b>${esc(application.alias || fallback)}</b><small class="ca-trust-ratio">${esc(ratio)}</small>${versions.map(version => `<small>${esc(version)}</small>`).join('')}</span></span>`;
        }).join('');
        const rows = orderedFamilies.flatMap(([, group]) => group.stores.map(store => ({
            application: group.application, store
        }))).sort((left, right) => {
            const order = {current: 0, common: 1, unknown: 2, retained: 3};
            const leftGroup = families.get(left.application.id);
            const rightGroup = families.get(right.application.id);
            const priority = group => groupState(group) === 'trusted' ? 0
                : group.application.recognized ? 1 : 2;
            return priority(leftGroup) - priority(rightGroup)
                || String(left.application.alias).localeCompare(String(right.application.alias))
                || (order[left.store.snap_lifecycle] ?? 2) - (order[right.store.snap_lifecycle] ?? 2);
        }).map(({application, store}) => `<tr class="snap-${esc(store.snap_lifecycle || 'none')}"><td><b>${esc(application.alias || skewerStoreFamily(store))}</b><small>${esc(store.label || '')}</small></td><td>${store.system ? 'System' : 'NSS'}</td><td>${esc(store.snap_name ? skewerStoreVariant(store) : '—')}</td><td class="${store.installed ? 'trusted' : ''}">${esc(store.installed ? 'důvěryhodné' : store.detail || 'CA nenalezena')}</td><td><code title="${esc(store.path || '')}">${esc(store.path || '—')}</code></td></tr>`).join('');
        const wasOpen = document.querySelector('.host-report-details')?.open;
        const showUnconfigured = localStorage.getItem('saslik-show-unconfigured-apps') === '1';
        $('skewer-trust-content').innerHTML =
            `<details class="host-report-details" ${wasOpen ? 'open' : ''}><summary class="host-report-meta"><span><i class="${report.online ? 'online' : 'offline'}"></i><b>${esc(report.hostname)}</b><small>${report.online ? 'online' : 'offline'}</small></span><span class="host-report-more">details <em>›</em></span></summary><div class="host-report-details-meta"><span>Skewer <b>${esc(report.skewer_version || '—')}</b></span><span>poslední report <b>${esc(updated)}</b></span></div><div class="host-report-table-wrap"><table class="host-report-table"><thead><tr><th>Store / profil</th><th>Typ</th><th>Snap revize</th><th>CA stav</th><th>Přesné umístění</th></tr></thead><tbody>${rows || '<tr><td colspan="5">Skewer zatím nereportoval žádné CA stores.</td></tr>'}</tbody></table></div></details><div class="ca-app-toolbar"><label><input type="checkbox" data-show-unconfigured ${showUnconfigured ? 'checked' : ''}> Show unconfigured apps</label><small>0/N bez instalované CA</small></div><div class="ca-app-strip ${showUnconfigured ? '' : 'hide-unconfigured'}">${compact}</div>`;
        const visibilityToggle = $('skewer-trust-content').querySelector('[data-show-unconfigured]');
        visibilityToggle.onchange = () => {
            localStorage.setItem('saslik-show-unconfigured-apps', visibilityToggle.checked ? '1' : '0');
            $('skewer-trust-content').querySelector('.ca-app-strip')
                ?.classList.toggle('hide-unconfigured', !visibilityToggle.checked);
        };
    } catch (_) {
        // A disconnected reporter must not disturb the rest of the dashboard.
    }
}
