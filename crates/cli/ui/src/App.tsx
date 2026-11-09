import { useState } from "react";
import {
  Content,
  ContentVariants,
  Label,
  Masthead,
  MastheadBrand,
  MastheadContent,
  MastheadMain,
  MastheadToggle,
  Nav,
  NavItem,
  NavList,
  Page,
  PageSection,
  PageSidebar,
  PageSidebarBody,
  PageToggleButton,
} from "@patternfly/react-core";
import { ListIcon, PluggedIcon, UnpluggedIcon } from "@patternfly/react-icons";
import { useLiveTargets } from "./live";
import { AttachWizard } from "./components/AttachWizard";
import { TargetsPage } from "./components/TargetsPage";

type PageId = "targets" | "attach";

/** App shell: masthead (brand + daemon version + live badge) + sidebar nav. */
export function App() {
  const { targets, health, tunnel, live, loading, error, refresh } = useLiveTargets();
  const [page, setPage] = useState<PageId>("targets");

  const nav = (
    <Nav aria-label="Global">
      <NavList>
        <NavItem
          itemId="targets"
          isActive={page === "targets"}
          preventDefault
          to="#targets"
          onClick={() => setPage("targets")}
        >
          <ListIcon aria-hidden /> Targets
        </NavItem>
        <NavItem
          itemId="attach"
          isActive={page === "attach"}
          preventDefault
          to="#attach"
          onClick={() => setPage("attach")}
        >
          <PluggedIcon aria-hidden /> Attach sync
        </NavItem>
      </NavList>
    </Nav>
  );

  const masthead = (
    <Masthead>
      <MastheadToggle>
        <PageToggleButton id="nav-toggle" variant="plain" aria-label="Navigation toggle">
          <ListIcon aria-hidden />
        </PageToggleButton>
      </MastheadToggle>
      <MastheadMain>
        <MastheadBrand>
          <Content component={ContentVariants.a} href="/" onClick={(e) => e.preventDefault()}>
            sync-agent
          </Content>
        </MastheadBrand>
      </MastheadMain>
      <MastheadContent>
        <Content component={ContentVariants.small} className="pf-v6-u-color-200">
          daemon {health ? `v${health.version}` : "…"} · {targets.length} target
          {targets.length === 1 ? "" : "s"}
        </Content>
        {live ? (
          <Label color="green" icon={<PluggedIcon aria-hidden />} variant="outline">
            live
          </Label>
        ) : (
          <Label color="orange" icon={<UnpluggedIcon aria-hidden />} variant="outline">
            reconnecting
          </Label>
        )}
      </MastheadContent>
    </Masthead>
  );

  return (
    <Page masthead={masthead} sidebar={<PageSidebar isManagedSidebar>
      <PageSidebarBody usePageInsets>{nav}</PageSidebarBody>
    </PageSidebar>}>
      {page === "targets" ? (
        <TargetsPage
          targets={targets}
          tunnel={tunnel}
          loading={loading}
          error={error}
          onAttach={() => setPage("attach")}
          onDeleted={() => void refresh()}
        />
      ) : (
        <PageSection>
          <AttachWizard
            onFinished={() => {
              setPage("targets");
              void refresh();
            }}
          />
        </PageSection>
      )}
    </Page>
  );
}
