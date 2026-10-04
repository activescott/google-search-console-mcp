import assert from 'node:assert/strict';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const entry = resolve(process.env.GSC_TEST_ENTRY || 'build/index.js');
const mock = fileURLToPath(new URL('./google-api-mock.cjs', import.meta.url));
const { diagnoseAuthError, formatToolError, ADC_LOGIN_COMMAND, QUOTA_PROJECT_COMMAND } =
  await import(pathToFileURL(resolve(dirname(entry), 'auth-errors.js')));

// Shape of a Google API error as thrown by googleapis/gaxios: the useful
// detail is under response.data.error, not always in the top-level message.
function googleApiError({ message, status, structuredStatus, reason, innerMessage }) {
  const error = new Error(message);
  error.status = status;
  error.code = status;
  error.response = {
    status,
    data: {
      error: {
        code: status,
        message: innerMessage ?? message,
        status: structuredStatus,
        errors: reason ? [{ message: innerMessage ?? message, domain: 'global', reason }] : undefined,
      },
    },
  };
  return error;
}

test('structured 403 with no 403 or forbidden in the message is diagnosed', () => {
  const error = googleApiError({
    message: 'Request had insufficient authentication scopes.',
    status: 403,
    structuredStatus: 'PERMISSION_DENIED',
    reason: 'forbidden',
  });
  const diagnosis = diagnoseAuthError(error);
  assert.match(diagnosis, /^PERMISSION ERROR:/);
  assert.match(diagnosis, /does not have access to the requested Search Console property/);
  assert.match(diagnosis, /client_email/);
  assert.match(diagnosis, /not necessarily the active 'gcloud auth list' account/);
  assert.doesNotMatch(diagnosis, /gcloud auth list\n/);
});

test('403 carried only on response.status is diagnosed', () => {
  const error = new Error('The caller does not have permission');
  error.response = { status: 403, data: {} };
  assert.match(diagnoseAuthError(error), /^PERMISSION ERROR:/);
});

test('structured reason distinguishes a disabled API from a plain 403', () => {
  const error = googleApiError({
    message: 'Search Console API has not been used in project 1234 before or it is disabled.',
    status: 403,
    structuredStatus: 'PERMISSION_DENIED',
    reason: 'accessNotConfigured',
  });
  const diagnosis = diagnoseAuthError(error);
  assert.match(diagnosis, /^CONFIGURATION ERROR: The Search Console API is not enabled/);
  assert.match(diagnosis, /searchconsole\.googleapis\.com/);
});

test('missing quota project is diagnosed ahead of the generic 403', () => {
  const error = googleApiError({
    message: 'Your application is authenticating by using local Application Default Credentials. '
      + 'The searchconsole.googleapis.com API requires a quota project.',
    status: 403,
    structuredStatus: 'PERMISSION_DENIED',
    reason: 'forbidden',
  });
  const diagnosis = diagnoseAuthError(error);
  assert.match(diagnosis, /^CONFIGURATION ERROR: Application Default Credentials have no usable quota project/);
  assert.ok(diagnosis.includes(QUOTA_PROJECT_COMMAND));
});

test('expired reauth token asks for a single-line login command', () => {
  const diagnosis = diagnoseAuthError(new Error('invalid_rapt: reauth related error'));
  assert.match(diagnosis, /^AUTHENTICATION ERROR: Google requires re-authentication/);
  assert.ok(diagnosis.includes(ADC_LOGIN_COMMAND));
  assert.ok(ADC_LOGIN_COMMAND.split('\n').length === 1);
});

test('every login-only recovery mentions the quota project follow-up', () => {
  const unauthenticated = new Error('Request is missing required authentication credential.');
  unauthenticated.response = { status: 401, data: {} };
  for (const error of [new Error('invalid_rapt: reauth related error'), unauthenticated]) {
    const diagnosis = diagnoseAuthError(error);
    assert.ok(diagnosis.includes(ADC_LOGIN_COMMAND));
    assert.ok(diagnosis.includes(QUOTA_PROJECT_COMMAND), diagnosis);
  }
});

test('status carried only on response.data.error.code is diagnosed', () => {
  const error = new Error('The caller does not have permission');
  error.response = { data: { error: { code: 403, message: 'The caller does not have permission' } } };
  assert.match(diagnoseAuthError(error), /^PERMISSION ERROR:/);
});

test('missing credentials are diagnosed with both setup commands', () => {
  const diagnosis = diagnoseAuthError(new Error('Could not load the default credentials.'));
  assert.ok(diagnosis.includes(ADC_LOGIN_COMMAND));
  assert.ok(diagnosis.includes(QUOTA_PROJECT_COMMAND));
});

test('structured 401 is diagnosed as unauthenticated', () => {
  const error = googleApiError({
    message: 'Request is missing required authentication credential.',
    status: 401,
    structuredStatus: 'UNAUTHENTICATED',
    reason: 'unauthorized',
  });
  assert.match(diagnoseAuthError(error), /^AUTHENTICATION ERROR: The request was rejected as unauthenticated/);
});

test('the login command requests cloud-platform only for the quota project', () => {
  assert.match(ADC_LOGIN_COMMAND, /webmasters\.readonly/);
  assert.match(ADC_LOGIN_COMMAND, /cloud-platform/);
});

test('non-auth errors pass through with the tool name', () => {
  const error = new Error('startDate must be in YYYY-MM-DD format');
  assert.equal(diagnoseAuthError(error), null);
  assert.equal(
    formatToolError('search_analytics', error),
    'Error in search_analytics: startDate must be in YYYY-MM-DD format'
  );
});

test('non-Error throwables do not crash the diagnosis', () => {
  assert.equal(diagnoseAuthError(undefined), null);
  assert.equal(diagnoseAuthError({ response: { status: 500 } }), null);
  assert.match(diagnoseAuthError({ response: { status: 403 } }), /^PERMISSION ERROR:/);
});

test('list_sites returns the permission guidance on a structured 403', { timeout: 15000 }, async () => {
  const dir = await mkdtemp(join(tmpdir(), 'gsc-403-test-'));
  const adcFile = join(dir, 'adc.json');
  await writeFile(adcFile, JSON.stringify({
    type: 'authorized_user', client_id: 'fake-client', client_secret: 'fake-secret',
    refresh_token: 'fake-refresh-token', quota_project_id: 'test-quota-project',
  }));

  const transport = new StdioClientTransport({
    command: process.execPath, args: ['--require', mock, entry], stderr: 'pipe',
    env: {
      GOOGLE_APPLICATION_CREDENTIALS: '', google_application_credentials: '',
      GOOGLE_CLOUD_PROJECT: 'test-project', GSC_TEST_ENTRY: entry, GSC_TEST_AUTH: 'adc',
      GSC_TEST_ADC_FILE: adcFile, GSC_TEST_SITES_ERROR: 'structured-403',
    },
  });
  const client = new Client({ name: 'gsc-403-test', version: '1.0.0' });
  try {
    await client.connect(transport);
    const result = await client.callTool({ name: 'list_sites', arguments: {} });
    assert.match(result.content[0].text, /^PERMISSION ERROR: Access denied by the Search Console API\./);
    assert.match(result.content[0].text, /To confirm which identity the server uses/);
  } finally {
    await client.close();
    await rm(dir, { recursive: true, force: true });
  }
});
