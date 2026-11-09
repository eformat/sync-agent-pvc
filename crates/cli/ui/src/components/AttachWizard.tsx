import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Button,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
  Form,
  FormGroup,
  HelperText,
  HelperTextItem,
  Radio,
  TextInput,
  TextArea,
  Wizard,
  WizardStep,
} from "@patternfly/react-core";
import { ApiError, api, errorMessage, isSlug } from "../api";
import { useToast } from "../toast";
import type { DryRunReport } from "../types";
import { DirPicker } from "./DirPicker";
import { DryRunView } from "./DryRunView";
import { PatternListEditor, RejectedPatternsAlert } from "./PatternListEditor";

/** Shown as the relay field placeholder — replace with your relay's multiaddr. */
const RELAY_PLACEHOLDER =
  "/ip4/203.0.113.42/tcp/4001/p2p/12D3KooWQqWcYxCifgqAsynZL2uJUd132gbG3XhZbCQZMs6Dq9Qc";

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

/**
 * Three-step attach flow: pick the laptop directory → sandbox details →
 * review, create (POST /api/targets) and an optional dry-run preview.
 */
export function AttachWizard({ onFinished }: { onFinished: () => void }) {
  const toast = useToast();

  // step 1
  const [root, setRoot] = useState<string | null>(null);
  // step 2
  const [sandbox, setSandbox] = useState("");
  const [workspace, setWorkspace] = useState("default");
  const [relay, setRelay] = useState("");
  const [excludes, setExcludes] = useState<string[]>([]);
  // The target name derives from the picked directory; the override is what
  // the user typed (null = still deriving). Existing names power the
  // collision check — "already exists" must surface BEFORE submit, not as a
  // 409 after it.
  const [nameOverride, setNameOverride] = useState<string | null>(null);
  const [existingNames, setExistingNames] = useState<string[]>([]);
  // Sandbox-side path quick-pick (M6): "default" = /sandbox/<name> (subpath
  // policy); "plans" = /sandbox/.opencode/plan — the OpenCode plan dir, whose
  // sandbox HOME is /sandbox (the subpath default is wrong for that case).
  const [remotePreset, setRemotePreset] = useState<"default" | "plans">("default");
  // step 3
  const [creating, setCreating] = useState(false);
  const [createErr, setCreateErr] = useState<string | null>(null);
  const [rejectErr, setRejectErr] = useState<ApiError | null>(null);
  const [created, setCreated] = useState(false);
  const [dryRun, setDryRun] = useState<DryRunReport | null>(null);
  const [dryRunning, setDryRunning] = useState(false);
  const [dryRunErr, setDryRunErr] = useState<string | null>(null);

  const dirName = root ? (root.split("/").filter(Boolean).pop() ?? "") : "";
  const derivedName = slugify(dirName);
  const name = slugify(nameOverride ?? dirName);
  const nameValid = name.length > 0 && isSlug(name);
  const nameTaken = existingNames.includes(name);
  const sandboxValid = sandbox.trim().length > 0;
  const canCreate = !!root && sandboxValid && nameValid && !nameTaken && !created;

  // Re-derive when the directory changes; load the collision set once.
  useEffect(() => setNameOverride(null), [root]);
  useEffect(() => {
    api
      .listTargets()
      .then((ts) => setExistingNames(ts.map((t) => t.name)))
      .catch(() => setExistingNames([]));
  }, []);

  const transport = relay.trim() ? "p2p" : "exec";
  // The sandbox-side path this wizard will create (review + POST body).
  const rootRemote =
    remotePreset === "plans" ? "/sandbox/.opencode/plan" : `/sandbox/${name || "…"}`;

  const create = useCallback(async () => {
    if (!root) return;
    setCreating(true);
    setCreateErr(null);
    setRejectErr(null);
    try {
      const snap = await api.createTarget({
        name,
        root,
        sandbox: sandbox.trim(),
        workspace: workspace.trim() || "default",
        ...(relay.trim() ? { relay: relay.trim() } : {}),
        ...(remotePreset === "plans" ? { root_remote: "/sandbox/.opencode/plan" } : {}),
        excludes: excludes.map((p) => p.trim()).filter((p) => p !== ""),
      });
      setCreated(true);
      toast("success", `Target ${snap.name} attached`, "A first sync pass is starting.");
    } catch (err) {
      if (err instanceof ApiError && err.rejected) setRejectErr(err);
      else setCreateErr(errorMessage(err));
    } finally {
      setCreating(false);
    }
  }, [root, name, sandbox, workspace, relay, excludes, remotePreset, toast]);

  const runDryRun = useCallback(async () => {
    setDryRunning(true);
    setDryRunErr(null);
    try {
      setDryRun(await api.dryRun(name));
    } catch (err) {
      setDryRunErr(errorMessage(err));
    } finally {
      setDryRunning(false);
    }
  }, [name]);

  const review = useMemo(
    () => (
      <DescriptionList isCompact columnModifier={{ lg: "1Col" }}>
        <DescriptionListGroup>
          <DescriptionListTerm>Name</DescriptionListTerm>
          <DescriptionListDescription>{name || <em>— enter a sandbox name first —</em>}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Local directory (root)</DescriptionListTerm>
          <DescriptionListDescription>
            {root ? <span className="mono">{root}</span> : <em>— pick a directory first —</em>}
          </DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Sandbox</DescriptionListTerm>
          <DescriptionListDescription>{sandbox.trim() || <em>—</em>}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Remote path</DescriptionListTerm>
          <DescriptionListDescription>
            <span className="mono">{rootRemote}</span>
          </DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Workspace</DescriptionListTerm>
          <DescriptionListDescription>{workspace.trim() || "default"}</DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Transport</DescriptionListTerm>
          <DescriptionListDescription>
            {transport === "p2p" ? (
              <>
                p2p — dial the agent over the relay
                <div className="mono wrap-anywhere">{relay.trim()}</div>
              </>
            ) : (
              <>exec — oc exec stdio into the sandbox pod</>
            )}
          </DescriptionListDescription>
        </DescriptionListGroup>
        <DescriptionListGroup>
          <DescriptionListTerm>Excludes</DescriptionListTerm>
          <DescriptionListDescription>
            {excludes.filter((p) => p.trim() !== "").length === 0 ? (
              <em>none</em>
            ) : (
              <ul style={{ margin: 0, paddingLeft: "1.25rem" }}>
                {excludes
                  .filter((p) => p.trim() !== "")
                  .map((p, i) => (
                    <li key={i} className="mono">
                      {p}
                    </li>
                  ))}
              </ul>
            )}
          </DescriptionListDescription>
        </DescriptionListGroup>
      </DescriptionList>
    ),
    [name, root, sandbox, workspace, transport, relay, excludes, rootRemote],
  );

  const step3Body = (
    <div>
      {review}
      <div style={{ display: "flex", gap: "0.5rem", marginTop: "1rem", alignItems: "center" }}>
        <Button variant="primary" isDisabled={!canCreate || creating} onClick={() => void create()}>
          {creating ? "Creating…" : created ? "Target created" : "Create target"}
        </Button>
        <Button
          variant="secondary"
          isDisabled={!created || dryRunning}
          onClick={() => void runDryRun()}
        >
          {dryRunning ? "Running dry run…" : "Run dry-run preview"}
        </Button>
      </div>
      {createErr && (
        <Alert variant="danger" isInline title="Could not create target" className="pf-v6-u-mt-md">
          {createErr}
        </Alert>
      )}
      {rejectErr && (
        <div className="pf-v6-u-mt-md">
          <RejectedPatternsAlert err={rejectErr} />
        </div>
      )}
      {created && (
        <Alert
          variant="success"
          isInline
          title={`Target ${name} attached`}
          className="pf-v6-u-mt-md"
        >
          A first pass is running in the background. The dry-run preview below (optional) shows
          what a pass would do without changing anything.
        </Alert>
      )}
      {dryRunErr && (
        <Alert variant="danger" isInline title="Dry run failed" className="pf-v6-u-mt-md">
          {dryRunErr}
        </Alert>
      )}
      {dryRun && (
        <div className="pf-v6-u-mt-md">
          <DryRunView report={dryRun} />
        </div>
      )}
      <p className="pf-v6-u-color-200 pf-v6-u-mt-lg">
        Use <strong>Finish</strong> to go back to the target list.
      </p>
    </div>
  );

  return (
    <Wizard
      header={
        <>
          <Content component={ContentVariants.h1}>Attach sync target</Content>
          <Content component={ContentVariants.p} className="pf-v6-u-color-200">
            Sync a local directory with a sandbox&apos;s PVC, bidirectionally.
          </Content>
        </>
      }
      onClose={onFinished}
      onSave={onFinished}
    >
      <WizardStep
        id="pick-dir"
        name="Local directory"
        footer={{ isNextDisabled: !root }}
      >
        <p className="pf-v6-u-mb-md">
          Browse to the directory on this laptop you want synced. Selecting a directory only picks
          it — nothing is created until the final step.
        </p>
        <DirPicker selected={root} onSelect={setRoot} />
      </WizardStep>

      <WizardStep id="details" name="Sandbox details">
        <Form>
          <FormGroup label="Sandbox name" isRequired fieldId="wizard-sandbox">
            <TextInput
              id="wizard-sandbox"
              isRequired
              value={sandbox}
              placeholder="sync-oc"
              onChange={(_, v) => setSandbox(v)}
            />
            <HelperText>
              <HelperTextItem>
                Sandbox CR name (full name, or short name like{" "}
                <span className="mono">sync-oc</span> resolved against the workspace).
              </HelperTextItem>
            </HelperText>
          </FormGroup>
          <FormGroup label="Target name" fieldId="wizard-name">
            <TextInput
              id="wizard-name"
              value={name}
              placeholder={derivedName || "pick a directory to derive the name"}
              onChange={(_, v) => setNameOverride(v)}
            />
            <HelperText>
              <HelperTextItem>
                Lowercase letters, digits and dashes — the key in the daemon config. Derived
                from the picked directory name; edit to override. The sandbox side lands at{" "}
                <span className="mono">{remotePreset === "plans" ? "/sandbox/.opencode/plan" : `/sandbox/${name || "…"}`}</span>{" "}
                (see Sandbox-side path below).
              </HelperTextItem>
              {name.length > 0 && !nameValid && (
                <HelperTextItem variant="error">Name must be a non-empty slug: a-z, 0-9, -</HelperTextItem>
              )}
              {nameValid && nameTaken && (
                <HelperTextItem variant="error">
                  A target named <span className="mono">{name}</span> already exists — pick
                  another name (existing: {existingNames.join(", ")})
                </HelperTextItem>
              )}
            </HelperText>
          </FormGroup>
          <FormGroup label="Sandbox-side path" fieldId="wizard-root-remote">
            <Radio
              id="wr-default"
              name="root-remote"
              label={`Default — /sandbox/<name> (its own directory)`}
              isChecked={remotePreset === "default"}
              onChange={() => setRemotePreset("default")}
            />
            <Radio
              id="wr-plans"
              name="root-remote"
              label="OpenCode plans — /sandbox/.opencode/plan"
              isChecked={remotePreset === "plans"}
              onChange={() => setRemotePreset("plans")}
            />
            <HelperText>
              <HelperTextItem>
                The PVC directory synced with the laptop root. The default keeps each target in
                its own directory; the OpenCode-plans preset points at the sandbox&apos;s shared
                plan directory (the sandbox OpenCode&apos;s HOME is <span className="mono">/sandbox</span>).
              </HelperTextItem>
            </HelperText>
          </FormGroup>
          <FormGroup label="Workspace" fieldId="wizard-workspace">
            <TextInput id="wizard-workspace" value={workspace} onChange={(_, v) => setWorkspace(v)} />
            <HelperText>
              <HelperTextItem>Sandbox workspace (namespace-side group); usually the default.</HelperTextItem>
            </HelperText>
          </FormGroup>
          <FormGroup label="Relay multiaddr (optional)" fieldId="wizard-relay">
            <TextArea
              id="wizard-relay"
              rows={2}
              value={relay}
              placeholder={RELAY_PLACEHOLDER}
              onChange={(_, v) => setRelay(v)}
            />
            <HelperText>
              <HelperTextItem>
                Leave empty to use the exec transport (oc exec stdio). With a relay, the daemon
                dials the sandbox agent over the relay.
              </HelperTextItem>
            </HelperText>
          </FormGroup>
          <FormGroup label="Excludes" fieldId="wizard-excludes">
            <PatternListEditor patterns={excludes} onChange={setExcludes} />
          </FormGroup>
        </Form>
      </WizardStep>

      <WizardStep id="review" name="Review + create" footer={{ nextButtonText: "Finish" }}>
        {step3Body}
      </WizardStep>
    </Wizard>
  );
}
