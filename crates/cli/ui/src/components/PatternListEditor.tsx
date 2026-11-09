import { Alert, Button, TextInput } from "@patternfly/react-core";
import { PlusIcon, TimesIcon } from "@patternfly/react-icons";
import { ApiError } from "../api";

/**
 * Editable list of exclude patterns (mutagen glob syntax). Pure UI: the parent
 * decides whether "Save" does a PUT (target card) or feeds the create body
 * (attach wizard).
 */
export function PatternListEditor({
  patterns,
  onChange,
  rowPlaceholder = "e.g. node_modules",
  addLabel = "Add pattern",
  emptyHint = 'No excludes — everything under the root is synced. Patterns follow mutagen glob syntax (e.g. "node_modules", "*.log", ".git").',
}: {
  patterns: string[];
  onChange: (next: string[]) => void;
  rowPlaceholder?: string;
  addLabel?: string;
  emptyHint?: string;
}) {
  return (
    <div>
      {patterns.length === 0 && (
        <p className="pf-v6-u-color-200 pf-v6-u-font-size-sm">{emptyHint}</p>
      )}
      {patterns.map((p, i) => (
        <div key={i} style={{ display: "flex", gap: "0.5rem", marginBottom: "0.5rem" }}>
          <TextInput
            aria-label={`Exclude pattern ${i + 1}`}
            value={p}
            placeholder={rowPlaceholder}
            onChange={(_, v) => onChange(patterns.map((x, j) => (j === i ? v : x)))}
          />
          <Button
            variant="control"
            aria-label={`Remove pattern ${i + 1}`}
            onClick={() => onChange(patterns.filter((_, j) => j !== i))}
          >
            <TimesIcon aria-hidden />
          </Button>
        </div>
      ))}
      <Button variant="link" isInline icon={<PlusIcon aria-hidden />} onClick={() => onChange([...patterns, ""])}>
        {addLabel}
      </Button>
    </div>
  );
}

/** Inline alert for the 400 {"error", "rejected":[…]} shape from the daemon. */
export function RejectedPatternsAlert({ err }: { err: ApiError }) {
  return (
    <Alert variant="danger" isInline title="Some patterns were rejected">
      <p className="wrap-anywhere">{err.message}</p>
      {err.rejected && err.rejected.length > 0 && (
        <ul>
          {err.rejected.map((r, i) => (
            <li key={i} className="mono wrap-anywhere">
              {r}
            </li>
          ))}
        </ul>
      )}
    </Alert>
  );
}
