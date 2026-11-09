import {
  Alert,
  Content,
  ContentVariants,
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
} from "@patternfly/react-core";
import { CheckCircleIcon, ExclamationTriangleIcon } from "@patternfly/react-icons";
import type { DryRunReport } from "../types";

function Row({ term, children }: { term: string; children: React.ReactNode }) {
  return (
    <DescriptionListGroup>
      <DescriptionListTerm>{term}</DescriptionListTerm>
      <DescriptionListDescription>{children}</DescriptionListDescription>
    </DescriptionListGroup>
  );
}

function StringList({ items }: { items: string[] }) {
  if (items.length === 0) return <span className="pf-v6-u-color-200">none</span>;
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

/** Human rendering of the daemon's DryRunReport (attach wizard preview). */
export function DryRunView({ report }: { report: DryRunReport }) {
  const clean =
    report.planned_removes === 0 &&
    report.planned_materializes === 0 &&
    report.conflicts_left.length === 0 &&
    report.problems.length === 0 &&
    report.failed === 0 &&
    report.halted === null;

  return (
    <div>
      <Content component={ContentVariants.p}>
        Preview of what the next real pass would do. A dry run <strong>changes nothing</strong> on
        either side.
      </Content>

      {clean && (
        <Alert
          variant="success"
          isInline
          title="In sync — a real pass would apply no changes"
          customIcon={<CheckCircleIcon aria-hidden />}
        />
      )}
      {report.planned_materializes > 0 && (
        <Alert
          variant="info"
          isInline
          title={`${report.planned_materializes} file(s) would be copied to the sandbox`}
        />
      )}
      {report.planned_removes > 0 && (
        <Alert
          variant="warning"
          isInline
          title={`${report.planned_removes} path(s) would be removed`}
        >
          Check these carefully — they are deletions the next real pass would perform.
        </Alert>
      )}
      {report.halted !== null && (
        <Alert variant="danger" isInline title="Pass would halt">
          <span className="wrap-anywhere">{report.halted}</span>
        </Alert>
      )}
      {report.problems.length > 0 && (
        <Alert variant="warning" isInline title={`${report.problems.length} problem(s)`}>
          <StringList items={report.problems} />
        </Alert>
      )}
      {report.conflicts_left.length > 0 && (
        <Alert variant="danger" isInline title={`${report.conflicts_left.length} conflict(s) would remain`}>
          <StringList items={report.conflicts_left} />
        </Alert>
      )}

      <DescriptionList isCompact columnModifier={{ lg: "2Col" }} className="pf-v6-u-mt-md">
        <Row term="Planned materializations">{report.planned_materializes}</Row>
        <Row term="Planned removals">{report.planned_removes}</Row>
        <Row term="Applied / deleted / failed (last pass)">
          {report.applied} / {report.deleted} / {report.failed}
        </Row>
        <Row term="Trusted base">
          {report.trust_base ? (
            <>
              <CheckCircleIcon aria-hidden color="green" /> yes
            </>
          ) : (
            <>
              <ExclamationTriangleIcon aria-hidden color="orange" /> no
            </>
          )}
        </Row>
        <Row term="Conflicts resolved">{report.conflicts_resolved.length}</Row>
        <Row term="Conflicts left">{report.conflicts_left.length}</Row>
        <Row term="Honored resolutions">
          <StringList items={report.honored} />
        </Row>
        <Row term="Paused">{report.paused ? "yes" : "no"}</Row>
      </DescriptionList>
    </div>
  );
}
