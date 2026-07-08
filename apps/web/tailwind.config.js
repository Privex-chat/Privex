/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        surface: "var(--color-bg)",
        elevated: "var(--color-bg-elevated)",
        raised: "var(--color-bg-raised)",
        input: "var(--color-bg-input)",
        overlay: "var(--color-bg-overlay)",
        header: "var(--color-bg-header)",

        "text-primary": "var(--color-text)",
        "text-secondary": "var(--color-text-secondary)",
        "text-muted": "var(--color-text-muted)",
        "text-subtle": "var(--color-text-subtle)",
        "text-placeholder": "var(--color-text-placeholder)",

        border: "var(--color-border)",
        "border-strong": "var(--color-border-strong)",
        "border-focus": "var(--color-border-focus)",

        accent: "var(--color-accent)",
        "accent-hover": "var(--color-accent-hover)",
        "accent-text": "var(--color-accent-text)",
        "accent-subtle": "var(--color-accent-subtle)",
        "accent-bg": "var(--color-accent-bg)",

        success: "var(--color-success)",
        "success-bg": "var(--color-success-bg)",
        warning: "var(--color-warning)",
        danger: "var(--color-danger)",
        "danger-hover": "var(--color-danger-hover)",
        "danger-bg": "var(--color-danger-bg)",
        "danger-subtle": "var(--color-danger-subtle)",
        offline: "var(--color-offline)",

        "announce-info-bg": "var(--color-announce-info-bg)",
        "announce-info-border": "var(--color-announce-info-border)",
        "announce-info-text": "var(--color-announce-info-text)",
        "announce-warn-bg": "var(--color-announce-warn-bg)",
        "announce-warn-border": "var(--color-announce-warn-border)",
        "announce-warn-text": "var(--color-announce-warn-text)",
        "announce-err-bg": "var(--color-announce-err-bg)",
        "announce-err-border": "var(--color-announce-err-border)",
        "announce-err-text": "var(--color-announce-err-text)",

        "progress-track-file": "var(--color-progress-track-file)",
        "progress-fill-file": "var(--color-progress-fill-file)",

        "qr-bg": "var(--color-qr-bg)",
        divider: "var(--color-divider)",

        "password-weak": "var(--color-password-weak)",
        "password-fair": "var(--color-password-fair)",
        "password-good": "var(--color-password-good)",
        "password-strong": "var(--color-password-strong)",
        "password-vstrong": "var(--color-password-very-strong)",
      },
    },
  },
  plugins: [],
};