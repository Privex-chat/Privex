// Minimal shared shell for placeholder screens (real UI lands in later sessions).
import type { ReactNode } from "react";

export default function Screen({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <main className="min-h-screen bg-surface text-text-primary p-6">
      <h1 className="text-xl font-semibold">{title}</h1>
      <div className="mt-4 text-text-secondary">{children}</div>
    </main>
  );
}
