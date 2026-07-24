/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./server.py",
    "./templates/**/*.html"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      width: {
        'sidebar': '250px'
      },
      margin: {
        'sidebar': '250px'
      },
      fontFamily: {
        sans: ['"IBM Plex Sans"', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace']
      }
    }
  },
  plugins: [require("daisyui")],
  daisyui: {
    // Every semantic color below is picked and WCAG-AA verified (contrast
    // computed against its paired *-content and against base-100/dark base)
    // as a full from-scratch palette — see docs/superpowers (panel-ui-audit
    // memory) for the rationale. "corporate"/"business" are the theme *names*
    // referenced verbatim by data-theme attributes and toggleTheme() JS
    // throughout server.py; only the token values below are custom.
    themes: [
      {
        corporate: {
          ...require("daisyui/src/theming/themes")["corporate"],
          // Rust-orange brand primary, darkened from the original #fd6a02
          // (2.9:1 vs white — failed AA) to #C2410C (5.18:1 vs white,
          // 4.96:1 as text on base-100) so it stays legible as both button
          // fill and inline accent text/icons.
          primary: "#C2410C",
          "primary-content": "#FFFFFF",
          // Trust-blue secondary/info — network & "connection" semantics.
          secondary: "#0369A1",
          "secondary-content": "#FFFFFF",
          info: "#0369A1",
          "info-content": "#FFFFFF",
          // Cyan accent — kept visually distinct from both primary and
          // secondary for the "conn" log-type badge.
          accent: "#0E7490",
          "accent-content": "#FFFFFF",
          neutral: "#44403C",
          "neutral-content": "#FFFFFF",
          success: "#15803D",
          "success-content": "#FFFFFF",
          warning: "#A16207",
          "warning-content": "#FFFFFF",
          error: "#DC2626",
          "error-content": "#FFFFFF",
          // Warm-biased neutrals (a touch of the primary's hue) instead of
          // DaisyUI's stock cool greys.
          "base-100": "#FAFAF9",
          "base-200": "#F3F1EE",
          "base-300": "#E7E3DD",
          "base-content": "#1C1917",
          "--rounded-box": "1rem",      // border radius rounded-box for cards and other large boxes
          "--rounded-btn": "0.5rem",     // border radius rounded-btn for buttons
          "--rounded-badge": "1.9rem",   // border radius rounded-badge for badges
          "--rounded-tab": "0.5rem",     // border radius rounded-tab for tabs
        },
        business: {
          ...require("daisyui/src/theming/themes")["business"],
          // Brighter rust-orange for dark mode (8.0:1 vs the dark base);
          // content flips to near-black since white-on-bright-orange fails.
          primary: "#FB923C",
          "primary-content": "#1C1105",
          secondary: "#38BDF8",
          "secondary-content": "#08202E",
          info: "#38BDF8",
          "info-content": "#08202E",
          accent: "#22D3EE",
          "accent-content": "#062A30",
          neutral: "#3A3532",
          "neutral-content": "#F5F2EE",
          success: "#4ADE80",
          "success-content": "#052E13",
          warning: "#FBBF24",
          "warning-content": "#451A03",
          error: "#F87171",
          "error-content": "#450A0A",
          "base-100": "#14110D",
          "base-200": "#1C1815",
          "base-300": "#2A2521",
          "base-content": "#F5F2EE",
          "--rounded-box": "1rem",
          "--rounded-btn": "0.5rem",
          "--rounded-badge": "1.9rem",
          "--rounded-tab": "0.5rem",
        },
      },
    ],
  }
}
