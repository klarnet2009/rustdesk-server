/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./server.py",
    "./templates/**/*.html"
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: {
          DEFAULT: '#0d6efd',
          hover: '#0b5ed7',
          light: 'rgba(13, 110, 253, 0.1)'
        },
        surface: {
          light: '#ffffff',
          dark: '#212529'
        },
        body: {
          light: '#f8f9fa',
          dark: '#1a1d21'
        }
      },
      width: {
        'sidebar': '250px'
      },
      margin: {
        'sidebar': '250px'
      },
      fontFamily: {
        mono: ['Consolas', 'Monaco', 'monospace']
      }
    }
  },
  plugins: [require("daisyui")],
  daisyui: {
    themes: [
      {
        corporate: {
          ...require("daisyui/src/theming/themes")["corporate"],
          primary: "#fd6a02",
          "primary-content": "#ffffff",
          accent: "#0d6efd",
          "accent-content": "#ffffff",
          "--rounded-box": "1rem",      // border radius rounded-box for cards and other large boxes
          "--rounded-btn": "0.5rem",     // border radius rounded-btn for buttons
          "--rounded-badge": "1.9rem",   // border radius rounded-badge for badges
          "--rounded-tab": "0.5rem",     // border radius rounded-tab for tabs
        },
        business: {
          ...require("daisyui/src/theming/themes")["business"],
          primary: "#fd6a02",
          "primary-content": "#ffffff",
          accent: "#0d6efd",
          "accent-content": "#ffffff",
          "--rounded-box": "1rem",
          "--rounded-btn": "0.5rem",
          "--rounded-badge": "1.9rem",
          "--rounded-tab": "0.5rem",
        },
      },
    ],
  }
}


