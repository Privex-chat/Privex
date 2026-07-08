import { create } from "zustand";
import { db } from "../db";

const SETTINGS_KEY = "theme";

export type ThemeMode = "dark" | "light" | "amoled";

interface ThemeState {
  mode: ThemeMode;
  init: () => Promise<void>;
  setMode: (m: ThemeMode) => Promise<void>;
}

export const useTheme = create<ThemeState>((set) => ({
  mode: "dark",
  init: async () => {
    const row = await db.settings.get(SETTINGS_KEY);
    const stored = row?.value as ThemeMode | undefined;
    if (stored && ["dark", "light", "amoled"].includes(stored)) {
      set({ mode: stored });
    }
  },
  setMode: async (m: ThemeMode) => {
    await db.settings.put({ key: SETTINGS_KEY, value: m });
    set({ mode: m });
  },
}));