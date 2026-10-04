/**
 * Scopes requested by the `gcloud auth application-default login` command in
 * the recovery instructions. Broader than the scope the server itself
 * requests at runtime (`webmasters.readonly`): `cloud-platform` is only there
 * so gcloud can attach a quota project to the credentials.
 */
export const ADC_LOGIN_SCOPES = [
  "https://www.googleapis.com/auth/webmasters.readonly",
  "https://www.googleapis.com/auth/cloud-platform",
];

export const ADC_LOGIN_COMMAND = `gcloud auth application-default login --scopes=${ADC_LOGIN_SCOPES.join(",")}`;

export const QUOTA_PROJECT_COMMAND =
  "gcloud auth application-default set-quota-project YOUR_PROJECT_ID";

const RECONNECT_INSTRUCTION =
  "IMPORTANT: After running the above, you MUST reconnect this MCP server for the new credentials to take effect. In Claude Code, type /mcp and select the server to reconnect it.";

const PROJECT_ID_INSTRUCTION =
  "Replace YOUR_PROJECT_ID with the Google Cloud project that has the Search Console API enabled. To list projects, run: gcloud projects list";

// Logging in again rewrites the credentials file. gcloud tries to attach the
// quota project itself but skips that silently when the account lacks
// permission, so a login-only recovery can land on the quota project error.
const QUOTA_PROJECT_FOLLOWUP = [
  "Logging in again can leave the credentials without a quota project. If the next call reports a missing quota project, also run:",
  "",
  `  ${QUOTA_PROJECT_COMMAND}`,
  "",
  PROJECT_ID_INSTRUCTION,
].join("\n");

/**
 * Which identity the server is actually using. The account shown by
 * `gcloud auth list` is the gcloud CLI's own account and can differ from the
 * account stored in Application Default Credentials, so that command is not a
 * reliable check.
 */
const IDENTITY_INSTRUCTION = [
  "To confirm which identity the server uses:",
  "  - If GOOGLE_APPLICATION_CREDENTIALS is set in the server's configuration, the identity is the client_email in that service account key file, and that email must be added as a user on the property in Search Console.",
  "  - Otherwise the identity is the Google account that last ran 'gcloud auth application-default login'. This is not necessarily the active 'gcloud auth list' account, which applies to the gcloud CLI only. Re-run the login command and note which account is selected in the browser to be sure.",
  "  - Calling list_sites shows every property the current identity can read.",
].join("\n");

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return isRecord(value) ? value : undefined;
}

/**
 * HTTP status codes carried by the error. Google API errors expose the status
 * in several places depending on the layer that threw: `status` and `code` on
 * the Gaxios error itself, `response.status`, and `response.data.error.code`.
 */
function collectStatuses(error: unknown): number[] {
  const statuses: number[] = [];
  const add = (value: unknown) => {
    if (typeof value === "number" && Number.isFinite(value)) {
      statuses.push(value);
    } else if (typeof value === "string" && /^\d{3}$/.test(value)) {
      statuses.push(Number(value));
    }
  };

  const root = asRecord(error);
  if (!root) return statuses;
  add(root.status);
  add(root.code);

  const response = asRecord(root.response);
  if (response) {
    add(response.status);
    const inner = asRecord(asRecord(response.data)?.error);
    if (inner) {
      add(inner.code);
      add(inner.status);
    }
  }

  return statuses;
}

/**
 * Non-numeric diagnostic strings carried by the error: the Node/Gaxios `code`,
 * the structured `status` enum (e.g. `PERMISSION_DENIED`), and the `reason`,
 * `domain`, and `message` of each entry in the structured `errors` array.
 * Some permission failures carry `403` and `forbidden` only in these fields,
 * with neither appearing in the top-level message.
 */
function collectCodes(error: unknown): string[] {
  const codes: string[] = [];
  const add = (value: unknown) => {
    if (typeof value === "string" && value.length > 0) codes.push(value);
  };
  const addDetails = (entries: unknown) => {
    if (!Array.isArray(entries)) return;
    for (const entry of entries) {
      const detail = asRecord(entry);
      if (!detail) continue;
      add(detail.reason);
      add(detail.domain);
      add(detail.message);
    }
  };

  const root = asRecord(error);
  if (!root) return codes;
  if (typeof root.code === "string" && !/^\d{3}$/.test(root.code)) {
    add(root.code);
  }
  add(root.status);
  addDetails(root.errors);

  const inner = asRecord(asRecord(asRecord(root.response)?.data)?.error);
  if (inner) {
    add(inner.status);
    add(inner.message);
    addDetails(inner.errors);
    addDetails(inner.details);
  }

  return codes;
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return JSON.stringify(error);
}

/**
 * Detect common Google API auth/config errors and return actionable fix
 * instructions. Returns null if the error is not a recognized auth issue.
 */
export function diagnoseAuthError(error: unknown): string | null {
  const statuses = collectStatuses(error);
  const haystack = [errorMessage(error), ...collectCodes(error)]
    .join("\n")
    .toLowerCase();
  const has = (...needles: string[]) =>
    needles.some((needle) => haystack.includes(needle));
  const hasStatus = (...codes: number[]) =>
    codes.some((code) => statuses.includes(code));

  // RAPT (Re-Auth Proof Token) expired — Google Workspace requires browser re-auth
  if (has("invalid_rapt", "reauth related error")) {
    return [
      "AUTHENTICATION ERROR: Google requires re-authentication (RAPT token expired).",
      "",
      "Tell the user to run the following command (must be a single line, do not add line breaks):",
      "",
      `  ${ADC_LOGIN_COMMAND}`,
      "",
      QUOTA_PROJECT_FOLLOWUP,
      "",
      RECONNECT_INSTRUCTION,
    ].join("\n");
  }

  // Missing or unusable quota project
  if (
    has(
      "quota project",
      "quota_project",
      "billing/quota",
      "userprojectmissing",
      "user_project_denied",
      "serviceusage.services.use",
      "unable to detect a project id"
    )
  ) {
    return [
      "CONFIGURATION ERROR: Application Default Credentials have no usable quota project.",
      "",
      "Tell the user to run the following command:",
      "",
      `  ${QUOTA_PROJECT_COMMAND}`,
      "",
      PROJECT_ID_INSTRUCTION,
      "The account also needs the serviceusage.services.use permission on that project.",
      "",
      RECONNECT_INSTRUCTION,
    ].join("\n");
  }

  // Refresh token revoked, expired, or granted without the required scopes
  if (has("invalid_grant", "invalid_scope", "insufficient scope")) {
    return [
      "AUTHENTICATION ERROR: The stored credentials are invalid, expired, or missing the required scopes.",
      "",
      "Tell the user to run these two commands (each must be a single line, do not add line breaks):",
      "",
      `  1. ${ADC_LOGIN_COMMAND}`,
      `  2. ${QUOTA_PROJECT_COMMAND}`,
      "",
      PROJECT_ID_INSTRUCTION,
      "",
      RECONNECT_INSTRUCTION,
    ].join("\n");
  }

  // No credentials at all. Matched on the full google-auth-library phrase:
  // "default credentials" alone also appears in the quota project error, which
  // is handled above.
  if (
    has(
      "could not load the default credentials",
      "could not refresh access token"
    )
  ) {
    return [
      "AUTHENTICATION ERROR: No credentials found.",
      "",
      "Tell the user to run these two commands (each must be a single line, do not add line breaks):",
      "",
      `  1. ${ADC_LOGIN_COMMAND}`,
      `  2. ${QUOTA_PROJECT_COMMAND}`,
      "",
      PROJECT_ID_INSTRUCTION,
      "A service account key path in GOOGLE_APPLICATION_CREDENTIALS works instead, if the user prefers that.",
      "",
      RECONNECT_INSTRUCTION,
    ].join("\n");
  }

  // Search Console API not enabled on the quota project. Checked before the
  // generic 403 branch because this is also returned as a 403.
  if (
    has(
      "has not been used in project",
      "is not enabled",
      "accessnotconfigured",
      "service_disabled"
    )
  ) {
    return [
      "CONFIGURATION ERROR: The Search Console API is not enabled in the Google Cloud project.",
      "",
      "Tell the user to enable it at:",
      "  https://console.cloud.google.com/marketplace/product/google/searchconsole.googleapis.com",
      "",
      "Select the project used as the quota project, then click 'Enable'.",
      "",
      RECONNECT_INSTRUCTION,
    ].join("\n");
  }

  // Credentials are valid but rejected for this resource
  if (
    hasStatus(403) ||
    has("forbidden", "permission_denied", "insufficientpermissions")
  ) {
    return [
      "PERMISSION ERROR: Access denied by the Search Console API.",
      "",
      "Possible causes:",
      "  - The authenticated identity does not have access to the requested Search Console property",
      "  - The quota project does not have the Search Console API enabled",
      "",
      IDENTITY_INSTRUCTION,
    ].join("\n");
  }

  // Credentials missing or no longer accepted at all
  if (hasStatus(401) || has("unauthenticated", "invalid authentication")) {
    return [
      "AUTHENTICATION ERROR: The request was rejected as unauthenticated.",
      "",
      "Tell the user to run the following command (must be a single line, do not add line breaks):",
      "",
      `  ${ADC_LOGIN_COMMAND}`,
      "",
      QUOTA_PROJECT_FOLLOWUP,
      "",
      RECONNECT_INSTRUCTION,
      "",
      IDENTITY_INSTRUCTION,
    ].join("\n");
  }

  return null;
}

/**
 * Format an error for tool output. Returns actionable instructions for
 * auth/config issues, or the raw error message for other failures.
 */
export function formatToolError(toolName: string, error: unknown): string {
  return (
    diagnoseAuthError(error) ?? `Error in ${toolName}: ${errorMessage(error)}`
  );
}
