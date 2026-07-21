// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// Mero TEE documentation — Astro Starlight with the shared Calimero theme
// (Zinc + #a5ff11 lime), ported from calimero-network/core.
export default defineConfig({
  site: 'https://calimero-network.github.io',
  // GitHub project Pages serve under /<repo>/. Change if a custom domain is used.
  base: '/mero-tee',
  integrations: [
    starlight({
      title: 'Mero TEE',
      description:
        'Attestation, key management, and the release pipeline for merod nodes running in a TEE — how Mero TEE proves what code is running and releases keys only to it.',
      logo: {
        light: './src/assets/logo-light.svg',
        dark: './src/assets/logo-dark.svg',
        alt: 'Calimero — Mero TEE',
        replacesTitle: true,
      },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/theme.css'],
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
        styleOverrides: {
          borderRadius: '0.5rem',
          borderColor: 'var(--sl-color-gray-6)',
          codeBackground: 'var(--sl-color-gray-7)',
          codeFontFamily: 'var(--sl-font-mono)',
          frames: {
            editorTabBarBackground: 'var(--sl-color-gray-6)',
            terminalTitlebarBackground: 'var(--sl-color-gray-6)',
          },
        },
      },
      lastUpdated: true,
      editLink: {
        baseUrl: 'https://github.com/calimero-network/mero-tee/edit/master/docs/',
      },
      head: [
        { tag: 'meta', attrs: { name: 'theme-color', content: '#09090b' } },
      ],
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/calimero-network/mero-tee',
        },
      ],
      // Explicit, grouped navigation (not autogenerate): Get started (tutorials)
      // → Understand (concepts) → How it works (runtime flows) → Operate.
      sidebar: [
        { label: 'Home', link: '/' },
        {
          label: 'Get started',
          items: ['build/getting-started', 'build/verify-a-release'],
        },
        {
          label: 'Understand',
          items: [
            'understand/system-overview',
            'understand/trust-model',
            'understand/components',
            'understand/fleet-sidecar',
            'understand/security',
            'understand/glossary',
          ],
        },
        {
          label: 'How it works',
          items: [
            'flows/attestation-flow',
            'flows/key-release',
            'flows/verification',
            'flows/policy-management',
          ],
        },
        {
          label: 'Operate',
          items: [
            'operate/deploy-node-image',
            'operate/config-reference',
            'operate/release-pipeline',
            'operate/runbooks',
            'operate/error-handling',
          ],
        },
      ],

    }),
  ],
});
