import { Fragment } from "react";
import { Label, Spinner } from "@patternfly/react-core";
import {
  CheckCircleIcon,
  CompressArrowsAltIcon,
  ExclamationTriangleIcon,
  PauseIcon,
  PluggedIcon,
  RandomIcon,
  TerminalIcon,
} from "@patternfly/react-icons";

/** Phase → colored status label (idle=grey check, syncing=blue spinner, paused=orange, error=red). */
export function PhaseLabel({ phase }: { phase: string }) {
  switch (phase) {
    case "syncing":
      return (
        <Label color="blue" icon={<Spinner size="sm" aria-label="sync in progress" />}>
          syncing
        </Label>
      );
    case "paused":
      return (
        <Label color="orange" icon={<PauseIcon aria-hidden />}>
          paused
        </Label>
      );
    case "error":
      return (
        <Label color="red" icon={<ExclamationTriangleIcon aria-hidden />}>
          error
        </Label>
      );
    default:
      return (
        <Label color="grey" icon={<CheckCircleIcon aria-hidden />}>
          idle
        </Label>
      );
  }
}

/** Transport badge: p2p (relay dial) vs exec (oc exec stdio). */
export function TransportLabel({ transport }: { transport: string }) {
  return transport === "p2p" ? (
    <Label color="teal" icon={<PluggedIcon aria-hidden />}>
      p2p
    </Label>
  ) : (
    <Label color="purple" icon={<TerminalIcon aria-hidden />}>
      exec
    </Label>
  );
}

/** The live p2p connection path (M4.5): green direct / amber relayed; exec
 * targets carry no path badge. */
export function PathLabel({ transport, path }: { transport: string; path: string }) {
  if (transport !== "p2p") return null;
  return path === "direct" ? (
    <Label color="green" icon={<CompressArrowsAltIcon aria-hidden />}>
      direct
    </Label>
  ) : (
    <Label color="orange" icon={<RandomIcon aria-hidden />} variant="outline">
      relayed
    </Label>
  );
}

/** Boolean state flags rendered as compact labels. */
export function FlagLabels({ archiveSaved, trustBase }: { archiveSaved: boolean; trustBase: boolean }) {
  return (
    <>
      {archiveSaved ? (
        <Label color="green" icon={<CheckCircleIcon aria-hidden />}>
          archive saved
        </Label>
      ) : (
        <Label color="grey" icon={<ExclamationTriangleIcon aria-hidden />} variant="outline">
          no archive
        </Label>
      )}
      {trustBase ? (
        <Label color="green" variant="outline">
          trusted base
        </Label>
      ) : (
        <Label color="orange" variant="outline">
          untrusted base
        </Label>
      )}
    </>
  );
}

/** Sandbox-side health labels (the daemon's per-pass probe): the running
 * agent's version + tunnel specs, and the MCP convention compliance. The
 * sandbox OpenCode MCP panel failing silently was a blind spot (2026-11-07)
 * — these labels surface it laptop-side. */
export function SandboxHealthLabels({
  status,
}: {
  status: import("../types").SandboxStatus | null | undefined;
}) {
  if (!status) return null;
  const agentLabel =
    status.agent_version === "none" ? (
      <Label color="red" variant="outline">
        agent: not running
      </Label>
    ) : (
      <Label color="green" variant="outline">
        agent v{status.agent_version}
      </Label>
    );
  return (
    <>
      {agentLabel}
      {status.tunnel.map((t) => (
        <Label key={t} color="blue" variant="outline">
          tunnel {t}
        </Label>
      ))}
      {status.mcp_binary ? (
        <Label color="green" variant="outline">
          mcp binary ok
        </Label>
      ) : (
        <Label color="red" variant="outline">
          mcp binary missing
        </Label>
      )}
      {status.mcp_config ? null : (
        <Label color="orange" variant="outline">
          opencode.json not updated
        </Label>
      )}
      {status.root_ok ? null : (
        <Label color="red" variant="outline">
          remote root missing
        </Label>
      )}
    </>
  );
}

/** Counter chip: value + unit, red when the value is a failure count. */
export function Counter({ value, unit }: { value: number; unit: string }) {  return (
    <Fragment>
      <span style={{ fontWeight: 700, color: value > 0 && unit === "failed" ? "var(--pf-t--color--red--v6, #a60000)" : undefined }}>
        {value}
      </span>{" "}
      <span className="pf-v6-u-color-200">{unit}</span>
    </Fragment>
  );
}
