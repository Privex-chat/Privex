import { create } from "zustand";
import { db } from "../db";

const SETTINGS_KEY = "screen_record_protection";

interface ScreenRecordState {
  enabled: boolean;
  init: () => Promise<void>;
  setEnabled: (v: boolean) => Promise<void>;
}

export const useScreenRecord = create<ScreenRecordState>((set) => ({
  enabled: false,
  init: async () => {
    const row = await db.settings.get(SETTINGS_KEY);
    set({ enabled: row?.value === true });
  },
  setEnabled: async (v: boolean) => {
    await db.settings.put({ key: SETTINGS_KEY, value: v });
    set({ enabled: v });
  },
}));
