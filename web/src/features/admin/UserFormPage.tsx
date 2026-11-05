import Alert from "@cloudscape-design/components/alert";
import Box from "@cloudscape-design/components/box";
import Button from "@cloudscape-design/components/button";
import Checkbox from "@cloudscape-design/components/checkbox";
import Container from "@cloudscape-design/components/container";
import ContentLayout from "@cloudscape-design/components/content-layout";
import CopyToClipboard from "@cloudscape-design/components/copy-to-clipboard";
import Form from "@cloudscape-design/components/form";
import FormField from "@cloudscape-design/components/form-field";
import Header from "@cloudscape-design/components/header";
import Input from "@cloudscape-design/components/input";
import Multiselect from "@cloudscape-design/components/multiselect";
import RadioGroup from "@cloudscape-design/components/radio-group";
import SpaceBetween from "@cloudscape-design/components/space-between";
import Spinner from "@cloudscape-design/components/spinner";
import Toggle from "@cloudscape-design/components/toggle";
import { useEffect, useState } from "react";
import { ErrorAlert, errorText, fieldErrorText } from "../../components/errors";
import { useI18n } from "../../i18n";
import { ApiError, type Api } from "../../services/api";
import type { Role, ScopeMode, UserInput, UserView } from "../../types/api";
import { generatePassword, MIN_PASSWORD_LENGTH } from "../auth/password";
import { roleSummary, useCustomRoles } from "./roles";
import { UserPermissions } from "./UserPermissions";

interface Props {
  admin: Api["admin"];
  /** Undefined to create a new user. */
  userId?: string;
  currentUserId: string;
  onDone: (message: string) => void;
  onCancel: () => void;
}

type Errors = Partial<
  Record<
    "username" | "displayName" | "role" | "password" | "namespaces" | "form",
    string
  >
>;
const knownFields = [
  "username",
  "displayName",
  "role",
  "password",
  "namespaces",
];

export function UserFormPage({
  admin,
  userId,
  currentUserId,
  onDone,
  onCancel,
}: Props) {
  const { t } = useI18n();
  const editing = userId !== undefined;
  const [loaded, setLoaded] = useState<UserView | null>(null);
  const [available, setAvailable] = useState<string[] | null>(null);
  const [scopeMode, setScopeMode] = useState<ScopeMode>("all");
  const [ownNamespace, setOwnNamespace] = useState("");
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<Role>("user");
  const customRoles = useCustomRoles(admin);
  const [password, setPassword] = useState("");
  const [allNamespaces, setAllNamespaces] = useState(false);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [allowOwn, setAllowOwn] = useState(false);
  const [disabled, setDisabled] = useState(false);
  const [errors, setErrors] = useState<Errors>({});
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState<unknown>(null);

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      admin.namespaces(),
      editing ? admin.getUser(userId) : Promise.resolve(null),
    ])
      .then(([ns, u]) => {
        if (cancelled) return;
        setAvailable(ns.items);
        setScopeMode(ns.mode);
        setOwnNamespace(ns.netcheckNamespace);
        if (u) {
          setLoaded(u);
          setDisplayName(u.displayName);
          setRole(u.role);
          setAllNamespaces(u.allNamespaces);
          setNamespaces(u.namespaces);
          setAllowOwn(u.allowNetcheckNamespace);
          setDisabled(u.disabled);
        }
      })
      .catch((err: unknown) => !cancelled && setLoadError(err));
    return () => {
      cancelled = true;
    };
  }, [admin, editing, userId]);

  const self = editing && userId === currentUserId;
  // SSO accounts take role and namespaces from the access rules.
  const sso = loaded?.source === "oidc";

  const submit = async () => {
    const e: Errors = {};
    if (
      !editing &&
      !/^[a-z0-9][a-z0-9._-]{2,63}$/.test(username.trim().toLowerCase())
    )
      e.username = t("users.form.usernameInvalid");
    if (!editing && [...password].length < MIN_PASSWORD_LENGTH)
      e.password = t("password.tooShort", { n: MIN_PASSWORD_LENGTH });
    if (
      !sso &&
      role !== "admin" &&
      !allNamespaces &&
      namespaces.length === 0 &&
      !allowOwn
    )
      e.namespaces = t("users.form.nsRequired");
    setErrors(e);
    if (Object.keys(e).length > 0) return;

    const body: UserInput = {
      displayName: displayName.trim(),
      role,
      allNamespaces,
      namespaces: allNamespaces ? [] : namespaces,
      disabled,
      allowNetcheckNamespace: allowOwn,
    };
    setBusy(true);
    try {
      if (editing) {
        await admin.updateUser(userId, body);
        onDone(t("users.updated", { name: loaded?.username ?? "" }));
      } else {
        const u = await admin.createUser({
          ...body,
          username: username.trim().toLowerCase(),
          password,
          disabled: false,
        });
        onDone(t("users.created", { name: u.username }));
      }
    } catch (err) {
      const d = err instanceof ApiError ? err.details[0] : undefined;
      if (d && knownFields.includes(d.field))
        setErrors({ [d.field]: fieldErrorText(t, d) });
      else setErrors({ form: d ? fieldErrorText(t, d) : errorText(t, err) });
    } finally {
      setBusy(false);
    }
  };

  if (loadError) return <ErrorAlert error={loadError} />;
  if (available === null || (editing && !loaded)) {
    return (
      <Box textAlign="center" padding="xxl">
        <Spinner size="large" />
      </Box>
    );
  }

  const nsOptions = [...new Set([...available, ...namespaces])].map((n) => ({
    value: n,
    label: n,
    description: available.includes(n) ? undefined : t("users.form.gone"),
  }));

  return (
    <ContentLayout
      header={
        <Header variant="h1">
          {editing
            ? t("users.form.editTitle", { name: loaded?.username ?? "" })
            : t("users.form.createTitle")}
        </Header>
      }
    >
      <form
        onSubmit={(ev) => {
          ev.preventDefault();
          void submit();
        }}
      >
        <Form
          errorText={errors.form}
          actions={
            <SpaceBetween direction="horizontal" size="xs">
              <Button formAction="none" variant="link" onClick={onCancel}>
                {t("common.cancel")}
              </Button>
              <Button variant="primary" formAction="submit" loading={busy}>
                {editing ? t("common.save") : t("users.create")}
              </Button>
            </SpaceBetween>
          }
        >
          <SpaceBetween size="l">
            <Container
              header={<Header variant="h2">{t("users.form.account")}</Header>}
            >
              <SpaceBetween size="m">
                <FormField
                  label={t("users.form.username")}
                  errorText={errors.username}
                  description={
                    editing
                      ? t("users.form.usernameFixed")
                      : t("users.form.usernameDesc")
                  }
                >
                  <Input
                    value={editing ? (loaded?.username ?? "") : username}
                    disabled={editing}
                    onChange={({ detail }) => setUsername(detail.value)}
                    ariaLabel={t("users.form.username")}
                  />
                </FormField>
                <FormField
                  label={t("users.form.display")}
                  errorText={errors.displayName}
                  description={t("users.form.displayDesc")}
                >
                  <Input
                    value={displayName}
                    disabled={sso}
                    onChange={({ detail }) => setDisplayName(detail.value)}
                    ariaLabel={t("users.form.display")}
                  />
                </FormField>
                {!editing && (
                  <FormField
                    label={t("users.form.tempPassword")}
                    errorText={errors.password}
                    description={t("users.form.tempPasswordDesc", {
                      n: MIN_PASSWORD_LENGTH,
                    })}
                    secondaryControl={
                      <SpaceBetween direction="horizontal" size="xs">
                        <Button
                          key="generate"
                          formAction="none"
                          onClick={() => setPassword(generatePassword())}
                        >
                          {t("password.generate")}
                        </Button>
                        {password !== "" && (
                          <CopyToClipboard
                            key="copy"
                            variant="icon"
                            textToCopy={password}
                            copySuccessText={t("common.copied")}
                            copyErrorText={t("common.copyFailed")}
                          />
                        )}
                      </SpaceBetween>
                    }
                  >
                    <Input
                      value={password}
                      onChange={({ detail }) => setPassword(detail.value)}
                      ariaLabel={t("users.form.tempPassword")}
                      autoComplete="new-password"
                    />
                  </FormField>
                )}
                {editing && (
                  <FormField
                    label={t("users.form.state")}
                    description={
                      self
                        ? t("users.form.stateSelf")
                        : t("users.form.stateDesc")
                    }
                  >
                    <Toggle
                      checked={!disabled}
                      disabled={self}
                      onChange={({ detail }) => setDisabled(!detail.checked)}
                    >
                      {disabled
                        ? t("users.form.disabled")
                        : t("users.form.enabled")}
                    </Toggle>
                  </FormField>
                )}
              </SpaceBetween>
            </Container>

            {sso && (
              <Alert type="info" header={t("users.sso.title")}>
                {t("users.sso.body", {
                  groups: loaded?.groups.join(", ") || "—",
                })}
              </Alert>
            )}
            {!sso && (
              <Container
                header={<Header variant="h2">{t("users.form.role")}</Header>}
              >
                <FormField
                  errorText={errors.role}
                  description={self ? t("users.form.roleSelf") : undefined}
                >
                  <RadioGroup
                    value={role}
                    onChange={({ detail }) => setRole(detail.value as Role)}
                    ariaLabel={t("users.form.role")}
                    items={[
                      {
                        value: "user",
                        label: t("users.form.role.user"),
                        description: t("users.form.role.user.desc"),
                        disabled: self,
                      },
                      {
                        value: "admin",
                        label: t("users.form.role.admin"),
                        description: t("users.form.role.admin.desc"),
                      },
                      ...customRoles.map((r) => ({
                        value: r.id,
                        label: r.name,
                        description: roleSummary(t, r),
                        disabled: self,
                      })),
                    ]}
                  />
                </FormField>
              </Container>
            )}
            {!sso && (
              <Container
                header={
                  <Header
                    variant="h2"
                    description={t("users.form.namespacesDesc")}
                  >
                    {t("users.form.namespaces")}
                  </Header>
                }
              >
                <SpaceBetween size="m">
                  {role === "admin" ? (
                    <Alert type="info">{t("users.form.adminAll")}</Alert>
                  ) : (
                    <>
                      <RadioGroup
                        value={allNamespaces ? "all" : "some"}
                        onChange={({ detail }) =>
                          setAllNamespaces(detail.value === "all")
                        }
                        ariaLabel={t("users.form.namespaces")}
                        items={[
                          {
                            value: "all",
                            label: t("users.form.scopeAll"),
                            description:
                              scopeMode === "all"
                                ? t("users.form.scopeAllDescAll")
                                : t("users.form.scopeAllDescList"),
                          },
                          {
                            value: "some",
                            label: t("users.form.scopeSome"),
                            description: t("users.form.scopeSomeDesc"),
                          },
                        ]}
                      />
                      {!allNamespaces && (
                        <FormField
                          label={t("users.form.allowed")}
                          errorText={errors.namespaces}
                          description={t("users.form.available", {
                            n: available.length,
                          })}
                        >
                          <Multiselect
                            selectedOptions={nsOptions.filter((o) =>
                              namespaces.includes(o.value),
                            )}
                            options={nsOptions}
                            filteringType="auto"
                            filteringPlaceholder={t("users.form.searchNs")}
                            placeholder={t("users.form.pick")}
                            onChange={({ detail }) =>
                              setNamespaces(
                                detail.selectedOptions
                                  .map((o) => o.value ?? "")
                                  .filter(Boolean),
                              )
                            }
                            ariaLabel={t("users.form.allowed")}
                            empty={t("users.form.noNs")}
                          />
                        </FormField>
                      )}
                    </>
                  )}
                  {ownNamespace && (
                    <FormField description={t("users.form.ownNsDesc")}>
                      <Checkbox
                        checked={allowOwn}
                        onChange={({ detail }) => setAllowOwn(detail.checked)}
                      >
                        {t("users.form.ownNs", { ns: ownNamespace })}
                      </Checkbox>
                    </FormField>
                  )}
                </SpaceBetween>
              </Container>
            )}
            {editing && userId && (
              <UserPermissions admin={admin} userId={userId} reload={0} />
            )}
          </SpaceBetween>
        </Form>
      </form>
    </ContentLayout>
  );
}
