(function () {
  const STORAGE_KEY = 'reverselab-theme';

  // 22 Discord-like client themes: solids + gradient "nitro-style" swatches.
  // value is stored in localStorage / data-theme.
  const THEMES = [
    { value: 'cinder', label: 'Cinder', scheme: 'dark', swatch: 'linear-gradient(135deg, #2b211c 0%, #4a3428 55%, #6b4a34 100%)' },
    { value: 'mint-apple', label: 'Mint Apple', scheme: 'light', swatch: 'linear-gradient(135deg, #d8f5e8 0%, #9fe3c4 45%, #5ecf9a 100%)' },
    { value: 'citrus-sherbert', label: 'Citrus Sherbert', scheme: 'light', swatch: 'linear-gradient(135deg, #ffe8c8 0%, #ffc58a 45%, #ff9f6b 100%)' },
    { value: 'retro-raincloud', label: 'Retro Raincloud', scheme: 'light', swatch: 'linear-gradient(135deg, #c9d7ff 0%, #d6c4ff 40%, #f0b7ff 100%)' },
    { value: 'hanami', label: 'Hanami', scheme: 'light', swatch: 'linear-gradient(135deg, #ffe3ef 0%, #ffd0e4 40%, #ffb7d5 100%)' },
    { value: 'sunrise', label: 'Sunrise', scheme: 'light', swatch: 'linear-gradient(135deg, #fff1d6 0%, #ffe0a8 45%, #ffc978 100%)' },
    { value: 'cotton-candy', label: 'Cotton Candy', scheme: 'light', swatch: 'linear-gradient(135deg, #ffe8f7 0%, #ffd0f0 40%, #ffb6e8 100%)' },
    { value: 'lofi', label: 'LoFi', scheme: 'light', swatch: 'linear-gradient(135deg, #e8f7ff 0%, #d7ecff 45%, #c7e0ff 100%)' },
    { value: 'desert-khaki', label: 'Desert Khaki', scheme: 'light', swatch: 'linear-gradient(135deg, #f3ecda 0%, #e7d9b8 50%, #d6c49a 100%)' },
    { value: 'sunset', label: 'Sunset', scheme: 'dark', swatch: 'linear-gradient(135deg, #4a1d3a 0%, #7a2f4d 40%, #c45b3c 100%)' },
    { value: 'chroma-glow', label: 'Chroma Glow', scheme: 'dark', swatch: 'linear-gradient(135deg, #1a0f3d 0%, #2b1f7a 35%, #1f6bff 70%, #22d3ee 100%)' },
    { value: 'forest', label: 'Forest', scheme: 'dark', swatch: 'linear-gradient(135deg, #0f1a12 0%, #1a3320 45%, #2f5d3a 100%)' },
    { value: 'crimson', label: 'Crimson Moon', scheme: 'dark', swatch: 'linear-gradient(135deg, #1a0a0c 0%, #3a1018 45%, #6b1824 100%)' },
    { value: 'midnight-blurple', label: 'Midnight Blurple', scheme: 'dark', swatch: 'linear-gradient(135deg, #0b0c1a 0%, #1a1b3a 45%, #2b2d6b 100%)' },
    { value: 'mars', label: 'Mars', scheme: 'dark', swatch: 'linear-gradient(135deg, #1a100c 0%, #3a2218 45%, #6b3a24 100%)' },
    { value: 'dusk', label: 'Dusk', scheme: 'dark', swatch: 'linear-gradient(135deg, #1a1528 0%, #2a2040 40%, #3d2f5c 100%)' },
    { value: 'under-the-sea', label: 'Under the Sea', scheme: 'dark', swatch: 'linear-gradient(135deg, #0a1a1c 0%, #12333a 40%, #1a4d55 100%)' },
    { value: 'retro', label: 'Retro', scheme: 'dark', swatch: 'linear-gradient(135deg, #1a1230 0%, #3a2060 40%, #6b3aa0 70%, #c45bff 100%)' },
    { value: 'neon-nights', label: 'Neon Nights', scheme: 'dark', swatch: 'linear-gradient(135deg, #0d1020 0%, #1a1840 35%, #3a2080 65%, #ff4fd8 100%)' },
    { value: 'sepia', label: 'Sepia', scheme: 'dark', swatch: 'linear-gradient(135deg, #2a2014 0%, #4a3820 50%, #6b5230 100%)' },
    { value: 'blurple', label: 'Blurple', scheme: 'dark', swatch: 'linear-gradient(135deg, #2b2d6b 0%, #3b3f9a 45%, #5865f2 100%)' },
    { value: 'dark', label: 'Dark', scheme: 'dark', swatch: 'linear-gradient(135deg, #1e1f22 0%, #2b2d31 55%, #313338 100%)' }
  ];

  // Keep old saved values working after rename.
  const ALIASES = {
    light: 'mint-apple',
    ash: 'dark',
    midnight: 'midnight-blurple',
    chroma: 'chroma-glow',
    grape: 'retro',
    mocha: 'sepia',
    onyx: 'under-the-sea',
    aurora: 'forest',
    'cotton-candy': 'cotton-candy',
    sunset: 'sunset',
    forest: 'forest',
    crimson: 'crimson',
    dusk: 'dusk',
    dark: 'dark'
  };

  const LIGHT_THEMES = new Set(THEMES.filter((t) => t.scheme === 'light').map((t) => t.value));
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = prefersDark ? 'dark' : 'mint-apple';

  function resolveTheme(value) {
    if (!value) return defaultTheme;
    if (THEMES.some((theme) => theme.value === value)) return value;
    if (ALIASES[value] && THEMES.some((theme) => theme.value === ALIASES[value])) return ALIASES[value];
    return defaultTheme;
  }

  function getSavedTheme() {
    try {
      return window.localStorage.getItem(STORAGE_KEY);
    } catch (error) {
      return null;
    }
  }

  function saveTheme(theme) {
    try {
      window.localStorage.setItem(STORAGE_KEY, theme);
    } catch (error) {
      // Ignore storage failures; the current page still switches theme.
    }
  }

  function syncSwitcher(theme) {
    const buttons = document.querySelectorAll('[data-theme-swatch]');
    buttons.forEach((button) => {
      const active = button.getAttribute('data-theme-swatch') === theme;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-checked', active ? 'true' : 'false');
    });

    const label = document.querySelector('[data-theme-current]');
    if (label) {
      const found = THEMES.find((item) => item.value === theme);
      label.textContent = found ? found.label : theme;
    }

    // legacy select support if present
    const select = document.querySelector('[data-theme-select]');
    if (select) select.value = theme;
  }

  function applyTheme(theme) {
    const normalized = resolveTheme(theme);
    document.documentElement.setAttribute('data-theme', normalized);
    document.documentElement.style.colorScheme = LIGHT_THEMES.has(normalized) ? 'light' : 'dark';
    syncSwitcher(normalized);
    return normalized;
  }

  function createSwitcher() {
    if (document.querySelector('[data-theme-switcher]')) return;

    const nav = document.querySelector('.main-nav');
    const headerContainer = document.querySelector('.site-header .container');
    const host = nav || headerContainer;
    if (!host) return;

    const wrapper = document.createElement('div');
    wrapper.className = 'theme-switcher';
    wrapper.setAttribute('data-theme-switcher', '');

    const toggle = document.createElement('button');
    toggle.type = 'button';
    toggle.className = 'theme-toggle';
    toggle.setAttribute('data-theme-toggle', '');
    toggle.setAttribute('aria-haspopup', 'true');
    toggle.setAttribute('aria-expanded', 'false');
    toggle.setAttribute('aria-label', 'Open theme picker');

    const toggleSwatch = document.createElement('span');
    toggleSwatch.className = 'theme-toggle-swatch';
    toggleSwatch.setAttribute('data-theme-toggle-swatch', '');

    const toggleText = document.createElement('span');
    toggleText.className = 'theme-toggle-text';
    toggleText.innerHTML = '主题 <span data-theme-current></span>';

    const caret = document.createElement('span');
    caret.className = 'theme-toggle-caret';
    caret.setAttribute('aria-hidden', 'true');
    caret.textContent = '▾';

    toggle.appendChild(toggleSwatch);
    toggle.appendChild(toggleText);
    toggle.appendChild(caret);

    const panel = document.createElement('div');
    panel.className = 'theme-panel';
    panel.setAttribute('data-theme-panel', '');
    panel.hidden = true;

    const title = document.createElement('div');
    title.className = 'theme-panel-title';
    title.textContent = '预览主题';

    const hint = document.createElement('p');
    hint.className = 'theme-panel-hint';
    hint.textContent = 'Discord 风格色板 · 点击 swatch 切换';

    const grid = document.createElement('div');
    grid.className = 'theme-swatch-grid';
    grid.setAttribute('role', 'radiogroup');
    grid.setAttribute('aria-label', 'Theme swatches');

    THEMES.forEach((theme) => {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'theme-swatch';
      button.setAttribute('data-theme-swatch', theme.value);
      button.setAttribute('role', 'radio');
      button.setAttribute('aria-checked', 'false');
      button.setAttribute('aria-label', theme.label);
      button.title = theme.label;
      button.style.background = theme.swatch;

      const check = document.createElement('span');
      check.className = 'theme-swatch-check';
      check.setAttribute('aria-hidden', 'true');
      check.textContent = '✓';
      button.appendChild(check);

      button.addEventListener('click', () => {
        const nextTheme = applyTheme(theme.value);
        saveTheme(nextTheme);
        const current = THEMES.find((item) => item.value === nextTheme);
        if (current) toggleSwatch.style.background = current.swatch;
        // keep panel open like Discord preview
      });

      grid.appendChild(button);
    });

    panel.appendChild(title);
    panel.appendChild(hint);
    panel.appendChild(grid);

    function setOpen(open) {
      panel.hidden = !open;
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      wrapper.classList.toggle('is-open', open);
    }

    toggle.addEventListener('click', (event) => {
      event.stopPropagation();
      setOpen(panel.hidden);
    });

    document.addEventListener('click', (event) => {
      if (!wrapper.contains(event.target)) setOpen(false);
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') setOpen(false);
    });

    wrapper.appendChild(toggle);
    wrapper.appendChild(panel);
    host.insertAdjacentElement('afterend', wrapper);

    const active = resolveTheme(document.documentElement.getAttribute('data-theme') || getSavedTheme());
    applyTheme(active);
    const current = THEMES.find((item) => item.value === active);
    if (current) toggleSwatch.style.background = current.swatch;
  }

  // Early apply for pages without head bootstrap.
  applyTheme(getSavedTheme());

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createSwitcher, { once: true });
  } else {
    createSwitcher();
  }
})();
