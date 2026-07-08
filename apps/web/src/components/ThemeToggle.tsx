import { useTheme, type ThemeMode } from "../store/theme";

const MODES: { value: ThemeMode; label: string }[] = [
  { value: "dark", label: "Dark" },
  { value: "light", label: "Light" },
  { value: "amoled", label: "AMOLED" },
];

export default function ThemeToggle() {
  const mode = useTheme((s) => s.mode);
  const setMode = useTheme((s) => s.setMode);

  return (
    <div>
      <div className="text-sm text-text-primary">Appearance</div>
      <p className="text-xs text-text-muted">
        AMOLED uses pure black for true contrast and minimal power on OLED screens.
      </p>
      <div className="mt-2 flex gap-2">
        {MODES.map((m) => (
          <button
            key={m.value}
            onClick={() => void setMode(m.value)}
            className={`rounded-lg px-3 py-1.5 text-sm transition-colors ${
              mode === m.value
                ? "bg-accent text-white"
                : "bg-elevated hover:bg-raised text-text-secondary"
            }`}
          >
            {m.label}
          </button>
        ))}
      </div>
    </div>
  );
}