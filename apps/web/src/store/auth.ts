import { create } from "zustand";

interface AuthState {
  authenticated: boolean;
  userId: string | null;
  // Session token lives in MEMORY ONLY (docs 4.9) - never localStorage/IndexedDB.
  // A page refresh drops it; the app re-authenticates from the stored keys.
  sessionToken: string | null;
  setSession: (token: string, userId: string) => void;
  setAuthenticated: (userId: string) => void;
  signOut: () => void;
}

export const useAuth = create<AuthState>((set) => ({
  authenticated: false,
  userId: null,
  sessionToken: null,
  setSession: (sessionToken, userId) => set({ sessionToken, userId }),
  setAuthenticated: (userId) => set({ authenticated: true, userId }),
  signOut: () => set({ authenticated: false, userId: null, sessionToken: null }),
}));
