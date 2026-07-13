import { useCallback, useEffect, useRef, useState } from "react";

export function useCopyToClipboard(timeout = 2000): [copied: boolean, copy: (text: string) => void] {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const requestId = useRef(0);

  useEffect(() => {
    return () => {
      clearTimeout(timer.current);
      requestId.current += 1;
    };
  }, []);

  const copy = useCallback(
    (text: string) => {
      clearTimeout(timer.current);
      const id = ++requestId.current;
      const promise = navigator.clipboard?.writeText(text);
      if (!promise) {
        setCopied(false);
        return;
      }
      promise.then(
        () => {
          if (id !== requestId.current) return;
          setCopied(true);
          timer.current = setTimeout(() => {
            if (id !== requestId.current) return;
            setCopied(false);
          }, timeout);
        },
        () => {
          if (id !== requestId.current) return;
          setCopied(false);
        },
      );
    },
    [timeout],
  );

  return [copied, copy];
}
