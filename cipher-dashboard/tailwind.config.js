/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'cipher-bg':      '#0B0F17',
        'cipher-surface': '#0F1520',
        'cipher-card':    '#131B2A',
        'cipher-border':  '#1E2D42',
        'cipher-cyan':    '#22D3EE',
        'cipher-purple':  '#A78BFA',
        'cipher-red':     '#F87171',
        'cipher-green':   '#4ADE80',
        'cipher-yellow':  '#FBBF24',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in':    'fadeIn 0.4s ease-out forwards',
        'slide-in':   'slideIn 0.3s ease-out forwards',
        'slide-up':   'slideUp 0.35s ease-out forwards',
        'glow-pulse': 'glowPulse 2.5s ease-in-out infinite',
      },
      keyframes: {
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideIn: {
          '0%':   { opacity: '0', transform: 'translateX(-10px)' },
          '100%': { opacity: '1', transform: 'translateX(0)' },
        },
        slideUp: {
          '0%':   { opacity: '0', transform: 'translateY(14px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        glowPulse: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(34,211,238,0.15)' },
          '50%':      { boxShadow: '0 0 20px rgba(34,211,238,0.4)' },
        },
      },
    },
  },
  plugins: [],
}
