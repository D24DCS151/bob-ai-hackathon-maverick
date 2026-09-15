/**
 * THREATICAP Client Stores
 * 
 * Zustand stores for managing client state including theme,
 * authentication status, and commander mode.
 */

import create from "zustand";
import { persist, createJSONStorage } from "zustand/middleware/persist";

// ===== Theme Store =====

export type ThemeMode = "dark" | "light" | "system";

export interface ThemeState {
  mode: ThemeMode;
  setMode: (mode: ThemeMode) => void;
  toggleMode: () => void;
  isDark: boolean;
}

export const useThemeStore = create<ThemeState>(
  persist(
    (set) => ({
      mode: "dark",
      setMode: (mode: ThemeMode) => set({ mode }),
      toggleMode: () =>
        set((state) => {
          if (state.mode === "system") {
            return { mode: state.isDark ? "dark" : "light" };
          }
          return { mode: state.mode === "dark" ? "light" : "dark" };
        }),
      get isDark() {
        if (this.mode === "system") {
          return window.matchMedia("(prefers-color-scheme: dark)").matches;
        }
        return this.mode === "dark";
      },
    }),
    {
      name: "threaticap-theme",
      storage: createJSONStorage(localStorage),
    }
  )
);

// ===== Commander Mode Store =====

export interface CommanderModeState {
  active: boolean;
  threatId: string | null;
  setActive: (active: boolean, threatId?: string) => void;
  toggle: (threatId?: string) => void;
}

export const useCommanderStore = create<CommanderModeState>((set) => ({
  active: false,
  threatId: null,
  setActive: (active: boolean, threatId?: string) =>
    set({ active, threatId }),
  toggle: (threatId?: string) =>
    set((state) => ({
      active: !state.active,
      threatId: threatId || state.threatId,
    })),
}));

// ===== Selected Threat Store =====

export interface SelectedThreatState {
  threatId: string | null;
  setThreatId: (id: string | null) => void;
  reset: () => void;
}

export const useSelectedThreat = create<SelectedThreatState>((set) => ({
  threatId: null,
  setThreatId: (id: string | null) => set({ threatId: id }),
  reset: () => set({ threatId: null }),
})));

// ===== TLP Filter Store =====

export interface TlpFilterState {
  tlps: TLP[];
  setTlp: (tlp: TLP) => void;
  toggleTlp: (tlp: TLP) => void;
  reset: () => void;
}

export const useTlpFilter = create<TlpFilterState>((set) => ({
  tlps: [],
  setTlp: (tlp: TLP) => set((state) => ({
    tlps: state.tlps.includes(tlp) 
      ? state.tlps.filter((t) => t !== tlp)
      : [...state.tlps, tlp],
  })),
  reset: () => set({ tlps: [] }),
})));

// ===== MITRE Tactic Store =====

export interface MitreTacticState {
  tactics: string[];
  addTactic: (tactic: string) => void;
  removeTactic: (tactic: string) => void;
  reset: () => void;
}

export const useMitreTactic = create<MitreTacticState>((set) => ({
  tactics: [],
  addTactic: (tactic: string) => set((state) => ({
    tactics: state.tactics.includes(tactic) 
      ? state.tactics.filter((t) => t !== tactic)
      : [...state.tactics, tactic],
  })),
  removeTactic: (tactic: string) => set((state) => ({
    tactics: state.tactics.filter((t) => t !== tactic),
  })),
  reset: () => set({ tactics: [] }),
})));
// Export helper for global access
export const stores = {
  theme: useThemeStore,
  commander: useCommanderStore,
  selectedThreat: useSelectedThreat,
  tlpFilter: useTlpFilter,
  mitreTactic: useMitreTactic,
};