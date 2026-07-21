(function () {
  const STORAGE_KEY = 'reverselab-theme';
  const LIGHT_THEMES = new Set(['light', 'cotton-candy']);
  const THEMES = [
    { value: 'dark', label: 'Discord Dark' },
    { value: 'light', label: 'Discord Light' },
    { value: 'ash', label: 'Ash / Darker' },
    { value: 'midnight', label: 'Midnight' },
    { value: 'chroma', label: 'Chroma Glow' },
    { value: 'dusk', label: 'Dusk' },
    { value: 'cotton-candy', label: 'Cotton Candy' },
    { value: 'sunset', label: 'Sunset' },
    { value: 'forest', label: 'Forest' },
    { value: 'crimson', label: 'Crimson' },
    { value: 'grape', label: 'Grape' },
    { value: 'mocha', label: 'Mocha' },
    { value: 'onyx', label: 'Onyx' },
    { value: 'aurora', label: 'Aurora' }
  ];

  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  const defaultTheme = prefersDark ? 'dark' : 'light';

  function normalizeTheme(value) {
    return THEMES.some((theme) => theme.value === value) ? value : defaultTheme;
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

  function applyTheme(theme) {
    const normalized = normalizeTheme(theme);
    document.documentElement.setAttribute('data-theme', normalized);
    document.documentElement.style.colorScheme = LIGHT_THEMES.has(normalized) ? 'light' : 'dark';
    const select = document.querySelector('[data-theme-select]');
    if (select) select.value = normalized;
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

    const label = document.createElement('label');
    label.className = 'sr-only';
    label.setAttribute('for', 'theme-select');
    label.textContent = 'Theme';

    const select = document.createElement('select');
    select.id = 'theme-select';
    select.className = 'theme-select';
    select.setAttribute('data-theme-select', '');
    select.setAttribute('aria-label', 'Select theme');

    THEMES.forEach((theme) => {
      const option = document.createElement('option');
      option.value = theme.value;
      option.textContent = theme.label;
      select.appendChild(option);
    });

    select.addEventListener('change', (event) => {
      const nextTheme = applyTheme(event.target.value);
      saveTheme(nextTheme);
    });

    wrapper.appendChild(label);
    wrapper.appendChild(select);
    host.insertAdjacentElement('afterend', wrapper);
    select.value = document.documentElement.getAttribute('data-theme') || defaultTheme;
  }

  applyTheme(getSavedTheme());

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', createSwitcher, { once: true });
  } else {
    createSwitcher();
  }
})();
