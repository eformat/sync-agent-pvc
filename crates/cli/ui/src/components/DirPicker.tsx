import { useCallback, useEffect, useState } from "react";
import {
  Alert,
  Breadcrumb,
  BreadcrumbItem,
  Button,
  Label,
  Spinner,
  TextInput,
} from "@patternfly/react-core";
import { CheckCircleIcon, FolderIcon, HomeIcon } from "@patternfly/react-icons";
import { api, errorMessage } from "../api";
import { absoluteTime, formatBytes } from "../live";
import type { FsListing } from "../types";

/**
 * Directory browser over GET /api/fs. Starts at $HOME ("~"); clicking a
 * directory descends into it, "Select this dir" picks the current listing's
 * path as the sync root.
 */
export function DirPicker({
  selected,
  onSelect,
}: {
  selected: string | null;
  onSelect: (path: string) => void;
}) {
  const [listing, setListing] = useState<FsListing | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [manual, setManual] = useState("");

  const load = useCallback(async (path?: string) => {
    setLoading(true);
    setError(null);
    try {
      setListing(await api.fs(path));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const current = listing?.path ?? "";
  const segments = current.split("/").filter((s) => s.length > 0);

  const join = (base: string, name: string) =>
    base.endsWith("/") ? `${base}${name}` : `${base}/${name}`;

  const enter = (name: string) => void load(join(current, name));

  const crumbs = [
    <BreadcrumbItem key="root" onClick={() => void load("/")}>
      /
    </BreadcrumbItem>,
    ...segments.map((seg, i) => {
      const target = "/" + segments.slice(0, i + 1).join("/");
      const isLast = i === segments.length - 1;
      return (
        <BreadcrumbItem key={target} onClick={isLast ? undefined : () => void load(target)}>
          {seg}
        </BreadcrumbItem>
      );
    }),
  ];

  return (
    <div>
      <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", marginBottom: "0.5rem" }}>
        <Button variant="control" icon={<HomeIcon aria-hidden />} onClick={() => void load("~")}>
          Home
        </Button>
        <TextInput
          aria-label="Path"
          placeholder="Type a path (~/x works) and press Enter"
          value={manual}
          onChange={(_, v) => setManual(v)}
          onKeyUp={(e) => {
            if (e.key === "Enter" && manual.trim()) {
              void load(manual.trim());
              setManual("");
            }
          }}
        />
        <Button
          variant="secondary"
          isDisabled={!manual.trim()}
          onClick={() => {
            void load(manual.trim());
            setManual("");
          }}
        >
          Go
        </Button>
      </div>

      <Breadcrumb>{crumbs}</Breadcrumb>

      {error && <Alert variant="danger" isInline title="Could not list directory">{error}</Alert>}
      {loading && <Spinner size="lg" aria-label="loading directory" />}
      {!loading && !error && listing && (
        <>
          <div className="dir-list" role="list" aria-label="Directory entries">
            {listing.entries.length === 0 && (
              <p className="pf-v6-u-color-200 pf-v6-u-p-sm">Empty directory.</p>
            )}
            {listing.entries.map((e) => (
              <div
                key={e.name}
                role="listitem"
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "0.5rem",
                  padding: "0.25rem 0.5rem",
                }}
              >
                <FolderIcon aria-hidden color={e.is_dir ? "#1f6ce0" : "#a3a3a3"} />
                {e.is_dir ? (
                  <Button variant="link" isInline onClick={() => enter(e.name)}>
                    {e.name}/
                  </Button>
                ) : (
                  <span className="pf-v6-u-color-200">{e.name}</span>
                )}
                <span className="pf-v6-u-color-200 pf-v6-u-font-size-xs" title={absoluteTime(e.modified_unix)}>
                  {e.is_dir ? "" : formatBytes(e.size)}
                </span>
              </div>
            ))}
          </div>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", marginTop: "0.75rem" }}>
            <Button variant="primary" icon={<CheckCircleIcon aria-hidden />} onClick={() => onSelect(current)}>
              Select this dir
            </Button>
            {selected && (
              <Label color="green" icon={<CheckCircleIcon aria-hidden />}>
                <span className="mono">{selected}</span>
              </Label>
            )}
          </div>
        </>
      )}
    </div>
  );
}
