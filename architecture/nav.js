/* mero-tee Architecture — Shared Navigation */
(function () {
  'use strict';

  const REPO = 'https://github.com/calimero-network/mero-tee';
  const PAGES_BASE = './';

  const NAV = [
    { section: 'Overview' },
    { label: 'Home', href: 'index.html', dot: '#f59e0b' },
    { label: 'System Overview', href: 'system-overview.html', dot: '#3b82f6' },
    { label: 'Components', href: 'components.html', dot: '#10b981' },
    { section: 'Trust & Attestation' },
    { label: 'Trust Model', href: 'trust-model.html', dot: '#10b981' },
    { label: 'Key Release Flow', href: 'key-release-flow.html', dot: '#8b5cf6' },
    { label: 'Attestation Flow', href: 'attestation-flow.html', dot: '#ec4899' },
    { label: 'Verification', href: 'verification.html', dot: '#f97316' },
    { section: 'Operations' },
    { label: 'Release Pipeline', href: 'release-pipeline.html', dot: '#3b82f6' },
    { label: 'Policy Management', href: 'policy-management.html', dot: '#84cc16' },
    { label: 'Runbooks', href: 'runbooks.html', dot: '#f59e0b' },
    { section: 'Reference' },
    { label: 'Components', href: 'components.html', dot: '#84cc16' },
    { label: 'Config Reference', href: 'config-reference.html', dot: '#f97316' },
    { label: 'Error Handling', href: 'error-handling.html', dot: '#ef4444' },
    { label: 'Glossary', href: 'glossary.html', dot: '#06b6d4' },
    { section: 'Operations' },
    { label: 'Runbooks', href: 'runbooks.html', dot: '#f59e0b' },
    { label: 'Policy Management', href: 'policy-management.html', dot: '#8b5cf6' },
  ];

  function currentPage() {
    const p = location.pathname;
    for (const item of NAV) {
      if (!item.href) continue;
      if (p.endsWith(item.href) || p.endsWith('/' + item.href)) return item.href;
    }
    if (p.endsWith('/') || p.endsWith('/architecture/') || p.endsWith('/architecture')) return 'index.html';
    return '';
  }

  function buildSidebar() {
    const sb = document.createElement('nav');
    sb.className = 'sidebar';
    sb.id = 'sidebar';

    const cur = currentPage();

    sb.innerHTML = `
      <div class="sidebar-logo">
        <h2>Calimero <em>mero-tee</em></h2>
        <p>Architecture Reference</p>
      </div>
      <div class="sidebar-search">
        <input type="text" id="nav-search" placeholder="Search pages..." autocomplete="off"/>
      </div>
      <div class="sidebar-nav" id="nav-links"></div>
      <div class="sidebar-footer">
        <a href="${REPO}" target="_blank" rel="noopener">GitHub &rarr;</a>
      </div>
    `;

    const linksEl = sb.querySelector('#nav-links');
    for (const item of NAV) {
      if (item.section) {
        const s = document.createElement('div');
        s.className = 'nav-section';
        s.textContent = item.section;
        linksEl.appendChild(s);
        continue;
      }
      const a = document.createElement('a');
      a.className = 'nav-link' + (item.sub ? ' sub' : '') + (item.href === cur ? ' active' : '');
      a.href = PAGES_BASE + item.href;
      a.innerHTML = `<span class="nav-dot" style="background:${item.dot}"></span>${item.label}`;
      a.dataset.label = item.label.toLowerCase();
      linksEl.appendChild(a);
    }

    document.body.prepend(sb);

    const btn = document.createElement('button');
    btn.className = 'menu-toggle';
    btn.textContent = '\u2630';
    btn.onclick = () => sb.classList.toggle('open');
    document.body.prepend(btn);

    const search = sb.querySelector('#nav-search');
    search.addEventListener('input', () => {
      const q = search.value.toLowerCase();
      linksEl.querySelectorAll('.nav-link').forEach(a => {
        a.style.display = a.dataset.label.includes(q) ? '' : 'none';
      });
      linksEl.querySelectorAll('.nav-section').forEach(s => {
        let hasVisible = false;
        let el = s.nextElementSibling;
        while (el && !el.classList.contains('nav-section')) {
          if (el.style.display !== 'none') hasVisible = true;
          el = el.nextElementSibling;
        }
        s.style.display = hasVisible ? '' : 'none';
      });
    });
  }

  function buildBreadcrumb(items) {
    const bc = document.querySelector('.breadcrumb');
    if (!bc) return;
    bc.innerHTML = items.map((item, i) => {
      if (i === items.length - 1) return `<span>${item.label}</span>`;
      return `<a href="${item.href}">${item.label}</a><span class="sep">/</span>`;
    }).join('');
  }

  function tabSystem() {
    document.querySelectorAll('[data-tabs]').forEach(container => {
      const tabs = container.querySelectorAll('.tab');
      const panels = container.parentElement.querySelectorAll('.panel');
      tabs.forEach(tab => {
        tab.addEventListener('click', () => {
          tabs.forEach(t => t.classList.remove('on'));
          panels.forEach(p => p.classList.remove('on'));
          tab.classList.add('on');
          const target = document.getElementById(tab.dataset.target);
          if (target) target.classList.add('on');
        });
      });
    });
  }

  function ghLink(path, line) {
    const base = REPO + '/blob/master/';
    const url = line ? base + path + '#L' + line : base + path;
    return `<a class="gh-link" href="${url}" target="_blank" rel="noopener">${path}</a>`;
  }

  document.addEventListener('DOMContentLoaded', () => {
    buildSidebar();
    tabSystem();
  });

  window.arch = { ghLink, buildBreadcrumb, REPO, PAGES_BASE };
})();
