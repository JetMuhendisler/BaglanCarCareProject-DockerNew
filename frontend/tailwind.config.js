/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Dark Mode Brand Colors (Pistachio)
        brand: {
          light: "#d9f99d", // lime-200
          DEFAULT: "#84cc16", // lime-500
          dark: "#4d7c0f", // lime-700
          accent: "#bef264", // lime-400
        },
        // Dark Mode Backgrounds
        dark: {
          bg: "#0f172a", // slate-900
          card: "#1e293b", // slate-800
          hover: "#334155", // slate-700
          border: "#334155", // slate-700
        }
      }
    },
  },
  plugins: [],
};
