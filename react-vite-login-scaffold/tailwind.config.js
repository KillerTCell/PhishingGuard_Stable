/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      },
      keyframes: {
        shake: {
          '0%, 100%': { transform: 'translateX(0)' },
          '25%, 75%': { transform: 'translateX(5px)' },
          '50%': { transform: 'translateX(-5px)' },
        }
      },
      animation: {
        shake: 'shake 150ms ease-in-out',
      }
    },
  },
  plugins: [],
}