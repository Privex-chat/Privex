import { useCallback, useRef, useState } from "react";

export function useCopyToClipboard(timeout = 2000): [copied: boolean, copy: (text: string) => void] {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();

  const copy = useCallback(
    (text: string) => {
      clearTimeout(timer.current);
      const promise = navigator.clipboard?.writeText(text);
      if (!promise) {
        setCopied(false);
        return;
      }
      promise.then(
        () => {
          setCopied(true);
          timer.current = setTimeout(() => setCopied(false), timeout);
        },
        () => setCopied(false),
      );
    },
    [timeout],
  );

  return [copied, copy];
}
