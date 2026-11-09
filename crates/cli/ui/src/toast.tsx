import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Alert, AlertGroup, Button } from "@patternfly/react-core";
import { TimesIcon } from "@patternfly/react-icons";
import { errorMessage } from "./api";

type ToastVariant = "success" | "danger" | "info" | "warning";

interface ToastItem {
  id: number;
  variant: ToastVariant;
  title: string;
  body?: string;
}

type PushToast = (variant: ToastVariant, title: string, body?: string) => void;

const ToastContext = createContext<PushToast>(() => {});

/** Report an action failure as a danger toast — failed actions are never silent. */
export function useToast(): PushToast {
  return useContext(ToastContext);
}

export function toastError(push: PushToast, title: string, err: unknown): void {
  push("danger", title, errorMessage(err));
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setItems((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const push = useCallback<PushToast>(
    (variant, title, body) => {
      const id = nextId.current++;
      setItems((prev) => [...prev, { id, variant, title, body }]);
      // Non-fatal toasts self-dismiss; failures stay until acknowledged.
      if (variant !== "danger") {
        window.setTimeout(() => dismiss(id), 6000);
      }
    },
    [dismiss],
  );

  const value = useMemo(() => push, [push]);

  return (
    <ToastContext.Provider value={value}>
      {children}
      <AlertGroup isToast isLiveRegion>
        {items.map((t) => (
          <Alert
            key={t.id}
            variant={t.variant}
            title={t.title}
            actionClose={
              <Button variant="plain" onClick={() => dismiss(t.id)} aria-label="Close alert">
                <TimesIcon aria-hidden />
              </Button>
            }
          >
            {t.body}
          </Alert>
        ))}
      </AlertGroup>
    </ToastContext.Provider>
  );
}
