// Component-specific settings belong to the workspace selected when opened.
(() => {
  const configurableComponents = new Set(['gretom']);
  const dialog = document.createElement('dialog');
  dialog.className = 'component-control';
  dialog.id = 'component-control';
  dialog.setAttribute('aria-labelledby', 'component-control-title');
  dialog.innerHTML = `<form><header><div><small id="component-control-workspace"></small><h2 id="component-control-title"></h2></div><button type="button" data-close aria-label="Zavřít">×</button></header><div data-fields></div><p data-message role="status"></p><footer><small data-note></small><button type="submit">Uložit nastavení</button></footer></form>`;
  document.body.append(dialog);
  const form = dialog.querySelector('form');
  const fields = dialog.querySelector('[data-fields]');
  const message = dialog.querySelector('[data-message]');
  const save = dialog.querySelector('[type=submit]');
  let context = null;
  let requestId = 0;
  let busy = false;
  dialog.querySelector('[data-close]').onclick = () => dialog.close();
  dialog.addEventListener('close', () => { requestId++; context = null; });

  async function openPanel(component, label) {
    if (busy || !settingsWorkspace) return;
    const request = ++requestId;
    context = {workspace: settingsWorkspace, component};
    const selected = context;
    fields.replaceChildren();
    message.textContent = '';
    save.hidden = true;
    save.disabled = true;
    dialog.querySelector('[data-note]').textContent = '';
    dialog.querySelector('#component-control-title').textContent = label;
    dialog.querySelector('#component-control-workspace').textContent = `Workspace: ${selected.workspace}`;
    dialog.showModal();
    if (component !== 'gretom') {
      message.textContent = 'Tato komponenta zatím nemá vlastní nastavení.';
      return;
    }
    message.textContent = 'Načítám nastavení…';
    try {
      const response = await fetch(`/api/workspace/settings?workspace=${encodeURIComponent(selected.workspace)}`, {cache: 'no-store'});
      const data = await response.json();
      if (request !== requestId) return;
      if (!response.ok) throw new Error(data.error || 'Nastavení nelze načíst.');
      const settings = Object.entries(data.settings || {}).filter(([, definition]) => definition.component === component);
      if (!settings.length) throw new Error('Nastavení Gretomu není dostupné. Načti nový backend šašlika.');
      for (const [key, definition] of settings) {
        const row = document.createElement('label');
        const title = document.createElement('span');
        title.textContent = definition.label;
        const input = document.createElement('input');
        input.name = key;
        input.type = typeof definition.value === 'boolean' ? 'checkbox' : definition.kind === 'integer' ? 'number' : 'text';
        if (input.type === 'checkbox') { input.checked = definition.value; row.className = 'control-toggle'; }
        else {
          input.value = definition.value;
          input.required = true;
          if (input.type === 'number') { input.min = definition.min; input.max = definition.max; input.step = 1; }
          else {
            input.maxLength = definition.kind === 'prefix' ? 48 : 15;
            input.pattern = definition.kind === 'prefix' ? '[A-Za-z0-9][A-Za-z0-9_\\-]{0,47}' : '[A-Za-z0-9][A-Za-z0-9_.:\\-]{0,14}';
            input.spellcheck = false;
          }
        }
        row.append(title, input);
        if (definition.description) { const hint = document.createElement('small'); hint.textContent = definition.description; row.append(hint); }
        fields.append(row);
      }
      message.textContent = '';
      dialog.querySelector('[data-note]').textContent = 'Uložené hodnoty se použijí při příštím startu nebo aktualizaci Gretomu.';
      save.hidden = false;
      save.disabled = false;
    } catch (error) { if (request === requestId) message.textContent = error.message; }
  }

  form.addEventListener('submit', async event => {
    event.preventDefault();
    if (!context || busy || save.disabled || !form.reportValidity()) return;
    const selected = context;
    const request = requestId;
    const settings = {};
    for (const input of fields.querySelectorAll('input')) {
      settings[input.name] = input.type === 'checkbox' ? input.checked : input.type === 'number' ? Number(input.value) : input.value;
    }
    busy = true;
    save.disabled = true;
    try {
      const response = await post('/api/workspace/settings', {workspace: selected.workspace, settings});
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Nastavení nelze uložit.');
      if (request === requestId) message.textContent = 'Nastavení uloženo. Použije se při příštím spuštění Gretomu.';
    } catch (error) { if (request === requestId) message.textContent = error.message; }
    finally { busy = false; if (request === requestId) save.disabled = false; }
  });

  document.querySelectorAll('#component-table .component-row').forEach(row => {
    const component = row.dataset.component || (row.classList.contains('saslik-version-row') ? 'saslik' : 'pcap-storage');
    if (!configurableComponents.has(component)) return;
    const title = row.querySelector('strong');
    const label = title.childNodes[0].textContent.trim();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'component-control-open';
    button.dataset.componentControl = component;
    button.textContent = '⚙';
    button.title = `Nastavení ${label}`;
    button.setAttribute('aria-label', `Nastavení ${label}`);
    button.onclick = () => openPanel(component, label);
    const actions = row.querySelector('.component-actions') || row.lastElementChild;
    actions.classList.add('component-actions');
    actions.append(button);
  });
})();
