import { useCallback, useEffect, useRef, useState } from "react";
import {
  Alert,
  Button,
  Card,
  CardBody,
  CardFooter,
  CardHeader,
  CardTitle,
  Content,
  ContentVariants,
  ExpandableSection,
  Flex,
  FlexItem,
  Modal,
  ModalBody,
  ModalFooter,
  ModalHeader,
  Progress,
  Spinner,
  Split,
  SplitItem,
} from "@patternfly/react-core";
import { PauseIcon, PlayIcon, SyncAltIcon, CompressIcon, ExpandIcon, TrashIcon } from "@patternfly/react-icons";
import { ApiError, api, errorMessage } from "../api";
import { absoluteTime, formatBytes, relativeTime, useNow } from "../live";
import { toastError, useToast } from "../toast";
import type { PassProgress, TargetSnapshot } from "../types";
import { Counter, FlagLabels, PathLabel, PhaseLabel, SandboxHealthLabels, TransportLabel } from "./labels";
import { PatternListEditor, RejectedPatternsAlert } from "./PatternListEditor";

function StringList({ items }: { items: string[] }) {
  return (
    <ul className="pf-v6-u-m-0" style={{ paddingLeft: "1.25rem" }}>
      {items.map((s, i) => (
        <li key={i} className="mono wrap-anywhere">
          {s}
        </li>
      ))}
    </ul>
  );
}

const STAGE_LABELS: Record<string, string> = {
  connecting: "Connecting to sandbox agent",
  scanning: "Scanning for changes",
  staging: "Staging files to sandbox",
  applying: "Applying changes",
  verifying: "Verifying convergence",
};

/** Live pass progress: a spinner for count-less stages, a byte bar for staging. */
function PassProgressRow({ p }: { p: PassProgress }) {
  const label = STAGE_LABELS[p.stage] ?? p.stage;
  if (p.files_total === 0) {
    // connecting / scanning / applying / verifying — no meaningful counts.
    return (
      <Split hasGutter className="pf-v6-u-mt-md" style={{ alignItems: "center" }}>
        <SplitItem>
          <Spinner size="sm" aria-label="pass progress" />
        </SplitItem>
        <SplitItem isFilled>
          <Content component={ContentVariants.small}>{label}…</Content>
        </SplitItem>
      </Split>
    );
  }
  // Determinate: bytes are the smoother metric for staging (one 90MB file vs
  // thousands of small ones); fall back to files.
  const pct =
    p.bytes_total > 0
      ? Math.min(100, Math.round((p.bytes_done / p.bytes_total) * 100))
      : Math.min(100, Math.round((p.files_done / p.files_total) * 100));
  return (
    <Progress
      className="pf-v6-u-mt-md"
      value={pct}
      title={label}
      label={`${p.files_done} / ${p.files_total} files · ${formatBytes(p.bytes_done)} / ${formatBytes(p.bytes_total)}`}
    />
  );
}

/** One sync target: live snapshot + control actions + expandable detail sections. */
export function TargetCard({
  snap,
  onDeleted,
}: {
  snap: TargetSnapshot;
  onDeleted?: () => void;
}) {
  const toast = useToast();
  const now = useNow();
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  // Details (counters, conflicts, excludes) collapse by default (2026-11-06:
  // "collapse the per-file sync panel details"). Cards that need
  // attention (an error, or outstanding conflicts) start expanded.
  const [expanded, setExpanded] = useState(
    snap.last_error !== null || snap.conflicts_left.length > 0,
  );

  // Section open state. Conflicts auto-open while any conflict is outstanding.
  const [conflictsOpen, setConflictsOpen] = useState(snap.conflicts_left.length > 0);
  const [honoredOpen, setHonoredOpen] = useState(false);
  const [problemsOpen, setProblemsOpen] = useState(snap.problems.length > 0);
  const [excludesOpen, setExcludesOpen] = useState(false);

  // Resolve clicks are per-path so one pending choice doesn't disable the rest.
  const [resolving, setResolving] = useState<Set<string>>(new Set());

  const doAction = useCallback(
    async (title: string, action: () => Promise<{ message: string }>) => {
      setBusy(true);
      try {
        const reply = await action();
        toast("success", title, reply.message);
      } catch (err) {
        toastError(toast, `${title} failed`, err);
      } finally {
        setBusy(false);
      }
    },
    [toast],
  );

  const pauseResume = () =>
    doAction(snap.paused ? "Resume" : "Pause", () =>
      snap.paused ? api.resume(snap.name) : api.pause(snap.name),
    );

  const syncNow = () => doAction("Sync now", () => api.syncNow(snap.name));

  const doDelete = async () => {
    setBusy(true);
    try {
      const reply = await api.deleteTarget(snap.name);
      toast("success", "Sync detached", reply.message);
      setConfirmDelete(false);
      onDeleted?.();
    } catch (err) {
      toastError(toast, "Delete failed", err);
    } finally {
      setBusy(false);
    }
  };

  const resolve = async (path: string, choice: "keep-local" | "keep-remote") => {
    setResolving((prev) => new Set(prev).add(path));
    try {
      const reply = await api.resolve(snap.name, path, choice);
      toast("success", "Conflict resolution recorded", reply.message);
    } catch (err) {
      toastError(toast, "Resolve failed", err);
    } finally {
      setResolving((prev) => {
        const next = new Set(prev);
        next.delete(path);
        return next;
      });
    }
  };

  const title = (
    <div>
      <Content component={ContentVariants.h2} className="pf-v6-u-m-0">
        {snap.name}
      </Content>
      <Content component={ContentVariants.small} className="pf-v6-u-color-200">
        <span className="mono wrap-anywhere">{snap.root}</span> → sandbox{" "}
        <strong>{snap.sandbox}</strong>
      </Content>
    </div>
  );

  return (
    <Card>
      <CardHeader
        actions={{
          actions: (
            <Split hasGutter>
              <SplitItem>
                <Button
                  variant={snap.paused ? "secondary" : "control"}
                  icon={snap.paused ? <PlayIcon aria-hidden /> : <PauseIcon aria-hidden />}
                  isDisabled={busy}
                  onClick={() => void pauseResume()}
                >
                  {snap.paused ? "Resume" : "Pause"}
                </Button>
              </SplitItem>
              <SplitItem>
                <Button
                  variant="primary"
                  icon={<SyncAltIcon aria-hidden />}
                  // Clickable during a held first-run preview even mid-pass: the
                  // alert explicitly says "press Sync now", and the API queues
                  // the confirmation behind the running pass (wake + flag).
                  isDisabled={busy || (snap.phase === "syncing" && !snap.first_preview)}
                  onClick={() => void syncNow()}
                >
                  Sync now
                </Button>
              </SplitItem>
              <SplitItem>
                <Button
                  variant="plain"
                  icon={<TrashIcon aria-hidden />}
                  isDisabled={busy}
                  aria-label={`Delete sync ${snap.name}`}
                  onClick={() => setConfirmDelete(true)}
                />
              </SplitItem>
              <SplitItem>
                <Button
                  variant="plain"
                  icon={
                    expanded ? (
                      <CompressIcon aria-hidden />
                    ) : (
                      <ExpandIcon aria-hidden />
                    )
                  }
                  aria-label={expanded ? `Collapse ${snap.name} details` : `Expand ${snap.name} details`}
                  onClick={() => setExpanded((e) => !e)}
                />
              </SplitItem>
            </Split>
          ),
          hasNoOffset: true,
        }}
      >
        <CardTitle>
          <Flex alignItems={{ default: "alignItemsCenter" }} gap={{ default: "gapSm" }}>
            <FlexItem>{title}</FlexItem>
            <FlexItem>
              <PhaseLabel phase={snap.phase} />
            </FlexItem>
            <FlexItem>
              <TransportLabel transport={snap.transport} />
            </FlexItem>
            <FlexItem>
              <PathLabel transport={snap.transport} path={snap.path} />
            </FlexItem>
          </Flex>
        </CardTitle>
      </CardHeader>
      {expanded && (
      <CardBody>
        {snap.first_preview && (
          <Alert
            variant="warning"
            isInline
            title="First-run preview held — nothing has propagated yet"
            style={{ marginBottom: "1rem" }}
          >
            The first pass ran as a <b>dry-run</b>: it would apply{" "}
            <b>{snap.first_preview.applied}</b> file(s) and delete{" "}
            <b>{snap.first_preview.deleted}</b>
            {snap.first_preview.conflicts_left.length > 0 && (
              <>, with <b>{snap.first_preview.conflicts_left.length}</b> conflict(s)</>
            )}
            . Review the counts below, then press <b>Sync now</b> to run it for real.
          </Alert>
        )}
        {snap.pass_progress && <PassProgressRow p={snap.pass_progress} />}
        <Flex gap={{ default: "gapMd" }} alignItems={{ default: "alignItemsCenter" }} wrap="wrap">
          <FlexItem>
            <Content component={ContentVariants.small}>
              Last pass:{" "}
              <span title={absoluteTime(snap.last_pass_unix)}>
                {relativeTime(snap.last_pass_unix, now)}
              </span>
            </Content>
          </FlexItem>
          <FlexItem>
            <Content component={ContentVariants.small}>
              <Counter value={snap.applied} unit="applied" /> ·{" "}
              <Counter value={snap.deleted} unit="deleted" /> ·{" "}
              <Counter value={snap.failed} unit="failed" />
            </Content>
          </FlexItem>
          <FlexItem>
            <FlagLabels archiveSaved={snap.archive_saved} trustBase={snap.trust_base} />
          </FlexItem>
          {snap.sandbox_status && (
            <FlexItem>
              <SandboxHealthLabels status={snap.sandbox_status} />
            </FlexItem>
          )}
        </Flex>

        {snap.last_error && (
          <Alert variant="danger" isInline title="Last pass failed" className="pf-v6-u-mt-md">
            <span className="wrap-anywhere">{snap.last_error}</span>
          </Alert>
        )}

        {/* Conflicts — each with an explicit laptop/sandbox choice. */}
        <ExpandableSection
          className="pf-v6-u-mt-md"
          toggleText={`Conflicts (${snap.conflicts_left.length})`}
          onToggle={(_, open) => setConflictsOpen(open)}
          isExpanded={conflictsOpen}
        >
          {snap.conflicts_left.length === 0 ? (
            <Content component={ContentVariants.small} className="pf-v6-u-color-200">
              No unresolved conflicts.
            </Content>
          ) : (
            snap.conflicts_left.map((path) => (
              <Split key={path} hasGutter className="pf-v6-u-my-sm" style={{ alignItems: "center" }}>
                <SplitItem isFilled>
                  <span className="mono wrap-anywhere">{path}</span>
                </SplitItem>
                <SplitItem>
                  <Button
                    variant="secondary"
                    isDisabled={resolving.has(path)}
                    size="sm"
                    onClick={() => void resolve(path, "keep-local")}
                  >
                    {resolving.has(path) ? <Spinner size="sm" /> : "Keep laptop"}
                  </Button>
                </SplitItem>
                <SplitItem>
                  <Button
                    variant="secondary"
                    isDisabled={resolving.has(path)}
                    size="sm"
                    onClick={() => void resolve(path, "keep-remote")}
                  >
                    {resolving.has(path) ? <Spinner size="sm" /> : "Keep sandbox"}
                  </Button>
                </SplitItem>
              </Split>
            ))
          )}
        </ExpandableSection>

        <HonoredSection
          snap={snap}
          open={honoredOpen}
          onToggle={(_, open) => setHonoredOpen(open)}
        />

        <ExpandableSection
          toggleText={`Problems (${snap.problems.length})`}
          onToggle={(_, open) => setProblemsOpen(open)}
          isExpanded={problemsOpen}
        >
          {snap.problems.length === 0 ? (
            <Content component={ContentVariants.small} className="pf-v6-u-color-200">
              No problems reported.
            </Content>
          ) : (
            <StringList items={snap.problems} />
          )}
        </ExpandableSection>

        <ExcludesSection snap={snap} open={excludesOpen} onToggle={(_, open) => setExcludesOpen(open)} />
      </CardBody>
      )}
      {expanded && (
      <CardFooter>
        <Content component={ContentVariants.small} className="pf-v6-u-color-200">
          daemon {snap.daemon_version}
        </Content>
      </CardFooter>
      )}
      <Modal
        isOpen={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        variant="small"
        aria-label={`Delete sync ${snap.name}`}
      >
        <ModalHeader title="Delete this sync?" labelId="delete-sync-title" />
        <ModalBody>
          <Content>
            <p>
              Detach <strong>{snap.name}</strong> ({" "}
              <span className="mono wrap-anywhere">{snap.root}</span> →{" "}
              <span className="mono">{snap.sandbox}</span>)?
            </p>
            <p className="pf-v6-u-color-200">
              The sync config and loop are removed. <strong>Files are untouched</strong> —
              neither the local directory nor the sandbox copy is deleted. Unsaved excludes
              edits are lost.
            </p>
          </Content>
        </ModalBody>
        <ModalFooter>
          <Button variant="danger" isDisabled={busy} onClick={() => void doDelete()}>
            {busy ? "Deleting…" : "Delete sync"}
          </Button>
          <Button variant="link" isDisabled={busy} onClick={() => setConfirmDelete(false)}>
            Cancel
          </Button>
        </ModalFooter>
      </Modal>
    </Card>
  );
}

/** Recent honored resolutions + resolved conflict paths from the last pass. */
function HonoredSection({
  snap,
  open,
  onToggle,
}: {
  snap: TargetSnapshot;
  open: boolean;
  onToggle: (ev: React.MouseEvent | React.KeyboardEvent, isOpen: boolean) => void;
}) {
  const total = snap.honored.length + snap.conflicts_resolved.length;
  return (
    <ExpandableSection toggleText={`Recent honored (${total})`} onToggle={onToggle} isExpanded={open}>
      {total === 0 ? (
        <Content component={ContentVariants.small} className="pf-v6-u-color-200">
          Nothing honored recently — sandbox-side or UI resolutions appear here after a pass.
        </Content>
      ) : (
        <>
          {snap.honored.length > 0 && <StringList items={snap.honored} />}
          {snap.conflicts_resolved.length > 0 && (
            <>
              <Content component={ContentVariants.small} className="pf-v6-u-color-200 pf-v6-u-mt-sm">
                Resolved on the last pass:
              </Content>
              <StringList items={snap.conflicts_resolved} />
            </>
          )}
        </>
      )}
    </ExpandableSection>
  );
}

/** Excludes editor: drafts locally, PUTs the full replacement list on Save. */
function ExcludesSection({
  snap,
  open,
  onToggle,
}: {
  snap: TargetSnapshot;
  open: boolean;
  onToggle: (ev: React.MouseEvent | React.KeyboardEvent, isOpen: boolean) => void;
}) {
  const toast = useToast();
  const [patterns, setPatterns] = useState<string[]>([]);
  const [baseline, setBaseline] = useState<string[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [rejectErr, setRejectErr] = useState<ApiError | null>(null);
  const [otherErr, setOtherErr] = useState<string | null>(null);
  const openRef = useRef(open);

  const load = useCallback(async () => {
    try {
      const list = await api.getExcludes(snap.name);
      setPatterns(list);
      setBaseline(list);
      setLoaded(true);
      setRejectErr(null);
      setOtherErr(null);
    } catch (err) {
      setOtherErr(errorMessage(err));
    }
  }, [snap.name]);

  // Lazy-load the current patterns the first time the section opens.
  useEffect(() => {
    if (open && !openRef.current && !loaded) void load();
    openRef.current = open;
  }, [open, loaded, load]);

  // Compare the cleaned draft (no blank rows) against the loaded list.
  const cleaned = patterns.map((p) => p.trim()).filter((p) => p !== "");
  const dirty = loaded && JSON.stringify(cleaned) !== JSON.stringify(baseline);

  const save = async () => {
    setSaving(true);
    setRejectErr(null);
    setOtherErr(null);
    try {
      const reply = await api.putExcludes(snap.name, cleaned);
      toast("success", "Excludes saved", reply.message);
      await load();
    } catch (err) {
      if (err instanceof ApiError && err.rejected) {
        setRejectErr(err);
      } else {
        setOtherErr(errorMessage(err));
      }
    } finally {
      setSaving(false);
    }
  };

  return (
    <ExpandableSection toggleText="Excludes" onToggle={onToggle} isExpanded={open}>
      {!loaded && !otherErr && <Spinner size="lg" aria-label="loading excludes" />}
      {otherErr && <Alert variant="danger" isInline title="Could not load excludes">{otherErr}</Alert>}
      {loaded && (
        <>
          <PatternListEditor patterns={patterns} onChange={setPatterns} />
          <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.75rem" }}>
            <Button variant="primary" isDisabled={saving || !dirty} onClick={() => void save()}>
              {saving ? "Saving…" : "Save"}
            </Button>
            <Button variant="link" isDisabled={saving} onClick={() => void load()}>
              Reset
            </Button>
          </div>
          {rejectErr && (
            <div className="pf-v6-u-mt-md">
              <RejectedPatternsAlert err={rejectErr} />
            </div>
          )}
        </>
      )}
    </ExpandableSection>
  );
}
