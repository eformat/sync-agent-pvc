import {
  Alert,
  Button,
  Content,
  ContentVariants,
  EmptyState,
  EmptyStateActions,
  EmptyStateBody,
  EmptyStateFooter,
  PageSection,
  Spinner,
  Stack,
  StackItem,
  Tab,
  Tabs,
  TextInputGroup,
  TextInputGroupMain,
} from "@patternfly/react-core";
import { SyncAltIcon } from "@patternfly/react-icons";
import { useMemo, useState } from "react";
import type { TargetSnapshot, TunnelStatus } from "../types";
import { PathLabel, TransportLabel } from "./labels";
import { TargetCard } from "./TargetCard";

/** Cards per target, sorted by name; empty state offers the attach wizard. */
export function TargetsPage({
  targets,
  tunnel,
  loading,
  error,
  onAttach,
  onDeleted,
}: {
  targets: TargetSnapshot[];
  tunnel: TunnelStatus | null;
  loading: boolean;
  error: string | null;
  onAttach: () => void;
  onDeleted?: () => void;
}) {
  // Group-by-sandbox tabs + a client-side filter (2026-11-06). The
  // sandbox group key is the part BEFORE the '+' — qualified ids
  // (`sync-oc+plan`) are per-root agents OF one sandbox.
  const [activeTab, setActiveTab] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  // Groups sorted by sandbox; the effective tab defaults to "All" when that
  // tab exists, else to the FIRST sandbox (an activeKey matching no rendered
  // tab makes PF render nothing — hit with a single sandbox, 2026-11-06).
  const groups = useMemo(() => {
    const m = new Map<string, TargetSnapshot[]>();
    for (const t of targets) {
      const key = t.sandbox.split("+")[0] || t.sandbox;
      if (!m.has(key)) m.set(key, []);
      m.get(key)!.push(t);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [targets]);

  const matches = (t: TargetSnapshot) => {
    const q = filter.trim().toLowerCase();
    if (!q) return true;
    return (
      t.name.toLowerCase().includes(q) ||
      t.root.toLowerCase().includes(q) ||
      t.sandbox.toLowerCase().includes(q) ||
      t.path.toLowerCase().includes(q)
    );
  };

  const shown = targets.filter(matches);
  const multiSandbox = groups.length > 1;
  const effectiveTab = activeTab ?? (multiSandbox ? "__all" : (groups[0]?.[0] ?? "__all"));

  // PF6 types Tabs children as TabElement (an internal type); a .map() of
  // <Tab> widens to Element[] and won't assign. The runtime accepts arrays of
  // Tab — build them in plain TS and bypass the check here.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any


  if (loading) {
    return (
      <PageSection>
        <EmptyState titleText="Loading targets" headingLevel="h2" icon={Spinner} />
      </PageSection>
    );
  }

  // Tabs always render ("i thought we tab per sandbox?"); with 2+
  // sandboxes an "All" tab joins them.


  const renderCards = (list: TargetSnapshot[]) =>
    list.length === 0 ? (
      <Content component={ContentVariants.small} className="pf-v6-u-color-200">
        No syncs match the filter.
      </Content>
    ) : (
      list.map((t) => (
        <StackItem key={t.name}>
          <TargetCard snap={t} onDeleted={onDeleted} />
        </StackItem>
      ))
    );

  const sandboxTabs: any = groups.map(([sb]) => (
    <Tab
      key={sb}
      eventKey={sb}
      title={`${sb} (${targets.filter((t) => (t.sandbox.split("+")[0] || t.sandbox) === sb).length})`}
    >
      <Stack hasGutter className="pf-v6-u-mt-md">
        {renderCards(shown.filter((t) => (t.sandbox.split("+")[0] || t.sandbox) === sb))}
      </Stack>
    </Tab>
  ));

  return (
    <PageSection>
      <Stack hasGutter>
        {error && (
          <StackItem>
            <Alert variant="danger" title="Could not reach the daemon">
              {error} — showing the last known state of each target.
            </Alert>
          </StackItem>
        )}
        {tunnel?.enabled && (
          <StackItem>
            <Alert
              variant={
                tunnel.link.agents > 0 || (tunnel.forwards ?? []).some((f) => f.listening)
                  ? "info"
                  : "warning"
              }
              isInline
              title="Tunnels"
            >
              {tunnel.services.length === 0 && (tunnel.forwards ?? []).length === 0
                ? "Enabled, but no services or forwards are configured."
                : tunnel.services.map((s) => (
                    <span
                      key={s.name}
                      style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}
                    >
                      <TransportLabel transport="p2p" />
                      {tunnel.link.agents > 0 && tunnel.link.direct > 0 && (
                        <PathLabel transport="p2p" path="direct" />
                      )}
                      {tunnel.link.agents > 0 && tunnel.link.relayed > 0 && (
                        <PathLabel transport="p2p" path="relayed" />
                      )}
                      <code className="mono">
                        {s.name} → {s.upstream}
                      </code>
                      <span>
                        {tunnel.link.agents} agent(s) connected, {s.refusals} refusal(s)
                      </span>
                    </span>
                  ))}
              {(tunnel.forwards ?? []).map((f) => (
                <span
                  key={f.target}
                  style={{ display: "flex", alignItems: "center", gap: "0.5rem", flexWrap: "wrap" }}
                >
                  <TransportLabel transport="p2p" />
                  {f.agent_link === "up" && f.path && (
                    <PathLabel transport="p2p" path={f.path} />
                  )}
                  <code className="mono">
                    attach ({f.target}) → 127.0.0.1:{f.local_port}
                  </code>
                  <span>
                    {f.agent_link === "up"
                      ? `agent link up · ${f.active_conns} conn(s)`
                      : `agent link ${f.agent_link}`}
                    {f.listening ? "" : " · listener down"}
                  </span>
                </span>
              ))}
            </Alert>
          </StackItem>
        )}
        {targets.length === 0 ? (
          <StackItem>
            <EmptyState
              titleText="No sync targets"
              headingLevel="h2"
              icon={SyncAltIcon}
            >
              <EmptyStateBody>
                Attach a local directory to a sandbox to start syncing your files to its PVC.
              </EmptyStateBody>
              <EmptyStateFooter>
                <EmptyStateActions>
                  <Button variant="primary" onClick={onAttach}>
                    Attach sync
                  </Button>
                </EmptyStateActions>
              </EmptyStateFooter>
            </EmptyState>
          </StackItem>
        ) : (
          <>
            <StackItem>
              <TextInputGroup>
                <TextInputGroupMain
                  type="search"
                  aria-label="Filter syncs"
                  placeholder="Filter syncs by name, folder, sandbox…"
                  value={filter}
                  onChange={(_, v) => setFilter(v)}
                />
              </TextInputGroup>
            </StackItem>
            <StackItem>
              <Tabs
                activeKey={effectiveTab}
                onSelect={(_, key) => setActiveTab(String(key))}
              >
                {multiSandbox && (
                  <Tab eventKey="__all" title={`All (${targets.length})`}>
                    <Stack hasGutter className="pf-v6-u-mt-md">
                      {renderCards(shown)}
                    </Stack>
                  </Tab>
                )}
                {sandboxTabs}
              </Tabs>
            </StackItem>
          </>
        )}
      </Stack>
    </PageSection>
  );
}
