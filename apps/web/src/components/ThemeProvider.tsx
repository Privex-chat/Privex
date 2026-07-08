import { useEffect, type ReactNode } from "react";
import { useTheme, type ThemeMode } from "../store/theme";

const THEME_ATTR = "data-theme";

function resolveOsPref(): "dark" | "light" {
  if (typeof window === "undefined") return "dark";
  return window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function applyThemeAttribute(mode: ThemeMode) {
  const root = document.documentElement;
  root.setAttribute(THEME_ATTR, mode);
  const meta = document.querySelector('meta[name="theme-color"]');
  const bg = getComputedStyle(root).getPropertyValue("--color-bg").trim() || "#0a0a0a";
  if (meta) meta.setAttribute("content", bg);
}

export default function ThemeProvider({ children }: { children: ReactNode }) {
  const mode = useTheme((s) => s.mode);
  const init = useTheme((s) => s.init);
  const setMode = useTheme((s) => s.setMode);

  useEffect(() => {
    void (async () => {
      await init();
      const current = useTheme.getState().mode;
      if (current === "dark" || current === "light" || current === "amoled") {
        applyThemeAttribute(current);
        return;
      }
      // First visit: no stored preference. Respect OS, default dark.
      const osPref = resolveOsPref();
      await setMode(osPref);
      applyThemeAttribute(osPref);
    })();
  }, [init, setMode]);

  useEffect(() => {
    applyThemeAttribute(mode);
  }, [mode]);

  return <>{children}</>;
}