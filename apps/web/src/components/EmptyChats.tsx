// Empty state for the Chats tab — the first thing a brand-new user sees. Privex
// has no directory to browse, so an empty screen with no guidance is a dead end.
// This turns it into a starting point: your own ID to share, a clear primary
// action, a 3-step "how it works", and a path to the full guide.
import { useNavigate } from "react-router-dom";
import { useAuth } from "../store/auth";
import { useCopyToClipboard } from "../hooks/useCopyToClipboard";
import Avatar from "./Avatar";

const STEPS = [
  {
    title: "Share your Privex ID",
    body: "Send the ID above to someone, or show your QR. That's all they need — no phone number, no email, no name.",
  },
  {
    title: "Add them back",
    body: "Tap “Add a contact” and paste their ID. They get a request to accept before either of you can message.",
  },
  {
    title: "Verify, then chat",
    body: "Compare safety codes once — over a call or in person. Matching codes prove no one is in the middle.",
  },
];

export default function EmptyChats() {
  const nav = useNavigate();
  const pxId = useAuth((s) => s.userId) ?? "";
  const [copied, copy] = useCopyToClipboard();

  return (
    <div className="mx-auto max-w-md py-8 text-center">
      {pxId && <Avatar seed={pxId} size={64} className="mx-auto" title="Your identicon" />}
      <h2 className="mt-4 text-lg font-semibold">No conversations yet</h2>
      <p className="mx-auto mt-1 max-w-sm text-sm text-text-secondary">
        Privex has no directory to search — you connect by exchanging IDs. Here&rsquo;s how to
        start your first chat.
      </p>

      {/* Your identity — the thing to share */}
      {pxId && (
        <div className="mt-6 rounded-xl border border-divider bg-elevated p-4 text-left">
          <div className="text-xs text-text-muted">Your Privex ID</div>
          <button
            type="button"
            onClick={() => copy(pxId)}
            title="Click to copy"
            className="mt-1 block w-full break-all text-left font-mono text-xs text-accent-subtle transition-colors hover:text-accent-hover"
          >
            {pxId}
          </button>
          <div className="mt-3 flex gap-2">
            <button
              onClick={() => copy(pxId)}
              className={
                "rounded-lg px-3 py-1.5 text-xs transition-colors " +
                (copied
                  ? "bg-success-bg text-white"
                  : "bg-raised text-text-secondary hover:bg-border-strong")
              }
            >
              {copied ? "Copied" : "Copy ID"}
            </button>
            <button
              onClick={() => nav("/my-qr")}
              className="rounded-lg bg-raised px-3 py-1.5 text-xs text-text-secondary transition-colors hover:bg-border-strong"
            >
              Show QR
            </button>
          </div>
        </div>
      )}

      {/* Primary action */}
      <button
        onClick={() => nav("/contacts")}
        className="mt-4 w-full rounded-lg bg-accent px-4 py-3 text-sm font-medium transition-colors hover:bg-accent-hover"
      >
        Add a contact
      </button>

      {/* How it works */}
      <ol className="mt-8 space-y-4 text-left">
        {STEPS.map((s, i) => (
          <li key={s.title} className="flex gap-3">
            <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-accent-bg text-xs font-semibold text-accent-text">
              {i + 1}
            </span>
            <div>
              <div className="text-sm font-medium">{s.title}</div>
              <p className="mt-0.5 text-xs leading-relaxed text-text-muted">{s.body}</p>
            </div>
          </li>
        ))}
      </ol>

      <button
        onClick={() => nav("/settings/guide")}
        className="mt-8 text-xs text-accent-text transition-colors hover:underline"
      >
        New to Privex? Read the guide →
      </button>
    </div>
  );
}
