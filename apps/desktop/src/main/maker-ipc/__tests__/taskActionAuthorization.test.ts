/**
 * Value: production tool admission + queued dispatch guards, no real account or network.
 * Regression: host wakes previously inherited scheduler/creator and Full Access write authority.
 * Gap: workbench tests cover visibility; SDK approval tests cannot prove Host consent.
 * Minimum input: automatic wake + send/stop/runtime tool; expect no queue/route change.
 * Tier: unit. This file isolates the process-local authorization lifetime from SQLite/IPC.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';
import { withToolCallAuthority } from '../../../../../../packages/lizi-mcps/src/tool-call-authority.js';
import type { AgentInputQueuedMessage } from '../../../shared/agentInputQueue.js';
import {
  approvedTaskDelegation,
  bindTaskActionInput,
  createTaskActionAuthorizer,
  taskActionInputGuard,
  hasTaskActionAuthorization,
  TASK_ACTION_TOOLS,
  ORCA_TASK_ACTION_TOOLS,
} from '../taskActionAuthorization.js';

function fixture(ownerInput = false, delegated = false) {
  let current = true;
  const confirm = vi.fn(async () => true);
  const authorize = createTaskActionAuthorizer({
    capture: async () => ({
      key: 'accepted-input',
      ownerInput,
      delegated,
      assertCurrent: async () => {
        if (!current) throw new Error('revoked');
      },
    }),
    confirm,
  });
  return {
    authorize,
    confirm,
    revoke: () => {
      current = false;
    },
  };
}
const call = (tool = 'continue_workbench_task') => ({
  sessionId: 'companion',
  server: 'cindy_helper' as const,
  tool,
  args: { task_id: 'task', message: 'Continue the approved work' },
});
const input = (): AgentInputQueuedMessage => ({
  clientId: 'queued',
  text: 'Approved body',
  persistedContent: 'Approved body',
  model: 'model',
  effort: '',
  permissionMode: 'bypassPermissions',
  workingDir: '/tmp/test',
  chatMessage: { clientId: 'queued', role: 'user', content: 'Approved body' },
  createOpts: { agentKind: 'codex', workingDir: '/tmp/test', model: 'model' },
  origin: {
    kind: 'session',
    senderSessionId: 'companion',
    senderBotId: 'bot',
    displayText: 'Approved body',
  },
});

describe('Host task action authorization', () => {
  it('permits observation and notification, but rejects every alternate task-write entrance before effects', async () => {
    const h = fixture();
    const queue: string[] = [];
    let route = 'original';
    for (const tool of TASK_ACTION_TOOLS) {
      const result = await withToolCallAuthority(h.authorize, call(tool), async () => {
        queue.push('unauthorized');
        route = 'changed';
        return { ok: true };
      });
      expect(result).toMatchObject({ isError: true });
    }
    for (const tool of ORCA_TASK_ACTION_TOOLS) {
      expect(
        await withToolCallAuthority(
          h.authorize,
          { ...call(tool), server: 'cindy_orca' },
          async () => {
            queue.push('unauthorized');
          },
        ),
      ).toMatchObject({ isError: true });
    }
    expect(queue).toEqual([]);
    expect(route).toBe('original');
    expect(h.confirm).not.toHaveBeenCalled();
    for (const tool of ['get_task_digest', 'get_workbench', 'schedule_notify_current_run']) {
      expect(
        await withToolCallAuthority(h.authorize, call(tool), async () => 'read-or-remind'),
      ).toBe('read-or-remind');
    }
  });

  it('binds a real confirmation to one exact invocation and consumes it once', async () => {
    const h = fixture(true);
    const request = call();
    const decision = await h.authorize(request);
    expect(h.confirm).toHaveBeenCalledWith('companion', request.tool, request.args);
    if (!decision.ok || !decision.run) throw new Error('missing Host grant');
    const operation = vi.fn(async () => 'sent');
    expect(await decision.run(operation)).toBe('sent');
    await expect(decision.run(operation)).rejects.toThrow('AUTHORIZATION_EXPIRED');
    expect(operation).toHaveBeenCalledTimes(1);
  });

  it.each(['task_id', 'message'] as const)(
    'rejects a changed %s after confirmation',
    async (key) => {
      const h = fixture(true),
        request = call();
      const decision = await h.authorize(request);
      request.args[key] = 'different';
      const operation = vi.fn(async () => 'sent');
      if (!decision.ok || !decision.run) throw new Error('missing Host grant');
      await expect(decision.run(operation)).rejects.toThrow('AUTHORIZATION_EXPIRED');
      expect(operation).not.toHaveBeenCalled();
    },
  );

  it('does not let approval racing with revocation execute', async () => {
    const h = fixture(true);
    h.confirm.mockImplementation(async () => {
      h.revoke();
      return true;
    });
    expect(await h.authorize(call())).toMatchObject({
      ok: false,
      errorCode: 'TASK_ACTION_AUTHORIZATION_EXPIRED',
    });
  });

  it('reuses a verified delegation without another confirmation and mints creation evidence only in the Host call', async () => {
    const h = fixture(false, true);
    expect(approvedTaskDelegation('companion')).toBeUndefined();
    expect(
      await withToolCallAuthority(
        h.authorize,
        call('message_session_task'),
        async () => 'continued',
      ),
    ).toBe('continued');
    expect(h.confirm).not.toHaveBeenCalled();
    const owner = fixture(true);
    const receipt = await withToolCallAuthority(
      owner.authorize,
      call('start_session_task'),
      async () => approvedTaskDelegation('companion'),
    );
    expect(receipt).toMatchObject({
      version: 1,
      actions: expect.arrayContaining(['message_session_task']),
    });
    expect(approvedTaskDelegation('companion')).toBeUndefined();
  });

  it('checks delayed input again, rejects target/content changes and cannot restore authority from JSON', async () => {
    const h = fixture(true),
      queued = input();
    await withToolCallAuthority(h.authorize, call(), async () => {
      bindTaskActionInput('target', queued);
    });
    await expect(taskActionInputGuard('target', queued)!()).resolves.toBeUndefined();
    await expect(taskActionInputGuard('another', queued)!()).rejects.toThrow(
      'AUTHORIZATION_EXPIRED',
    );
    await expect(
      taskActionInputGuard('target', { ...queued, text: 'different' })!(),
    ).rejects.toThrow('AUTHORIZATION_EXPIRED');
    await expect(
      taskActionInputGuard('target', JSON.parse(JSON.stringify(queued)))!(),
    ).rejects.toThrow('AUTHORIZATION_REQUIRED');
    h.revoke();
    await expect(taskActionInputGuard('target', queued)!()).rejects.toThrow('revoked');
  });

  it('holds old Bot queue rows on upgrade without deleting sent history or treating ordinary user input as automatic', async () => {
    await expect(taskActionInputGuard('target', input())!()).rejects.toThrow(
      'AUTHORIZATION_REQUIRED',
    );
    expect(taskActionInputGuard('target', { ...input(), origin: undefined })).toBeUndefined();
  });
});

// Regression #6399: the pure scope fixture above cannot detect lost group owner
// provenance or a second confirmation added to the owner's ordinary tool flow.
// Exercise the Desktop adapter + real group registry + shared helper/Orca entry.
// SQLite/account/routine IO is replaced with in-memory facts (unit tier).
const hostFacts = vi.hoisted(() => ({ getDb: vi.fn(), boundaryPending: vi.fn() }));
vi.mock('../../localDb/client/current.js', () => ({ tryGetDbClient: hostFacts.getDb }));
vi.mock('../../appSessionState.js', () => ({
  isAppSessionBoundaryPending: hostFacts.boundaryPending,
}));
vi.mock('../../routines/service.js', () => ({
  readActiveFollowUpRoutine: () => ({ enabled: false, revision: 1 }),
}));
import { createDesktopTaskActionAuthorizer } from '../taskActionHost.js';
import {
  registerGroupToolAuthority,
  GroupToolAuthorizationError,
} from '../botGroupToolAuthorization.js';

const releases: Array<() => void> = [];
afterEach(() => {
  releases.splice(0).forEach((release) => release());
});
function desktopFixture(kind: 'private' | 'group' | 'automatic' = 'group') {
  const caller = {
    source: 'bot',
    role: kind === 'group' ? 'group' : 'canonical',
    botId: 'bot',
    botStatus: 'active',
    status: 'active',
    archivedAt: null,
    clearedAt: null,
  };
  const query = {
    from: () => query,
    leftJoin: () => query,
    where: () => query,
    limit: async () => [caller],
  };
  const db = { drizzle: { select: () => query } };
  hostFacts.getDb.mockReturnValue(db);
  hostFacts.boundaryPending.mockReturnValue(false);
  const activeInput = {
    key: 'owner-request',
    ownerInput: kind === 'private',
    automatic: kind !== 'private',
    boundary: 'runtime-1',
  };
  const confirm = vi.fn(async () => true);
  const authorize = createDesktopTaskActionAuthorizer({ input: () => activeInput, confirm });
  return { authorize, confirm, activeInput, caller };
}
const ownerWrites = [
  ['cindy_helper', 'start_session_task'],
  ['cindy_helper', 'send_to_session'],
  ['cindy_helper', 'continue_workbench_task'],
  ['cindy_helper', 'set_session_runtime'],
  ['cindy_orca', 'create_worker'],
  ['cindy_orca', 'send_to_worker'],
] as const;

describe('Desktop owner input task actions', () => {
  it.each(['private', 'group'] as const)(
    'accepts %s owner input without a second confirmation, including downstream authorization',
    async (kind) => {
      const h = desktopFixture(kind);
      const validate = vi.fn(async () => {});
      if (kind === 'group')
        releases.push(
          registerGroupToolAuthority('companion', {
            botId: 'bot',
            mode: 'owner',
            isCurrent: () => true,
            validate,
          }),
        );
      for (const [server, tool] of ownerWrites) {
        const result = await withToolCallAuthority(
          h.authorize,
          { ...call(tool), server },
          async () => {
            expect(hasTaskActionAuthorization('companion')).toBe(true);
            if (tool === 'start_session_task')
              expect(approvedTaskDelegation('companion')).toMatchObject({ version: 1 });
            const queued = input();
            bindTaskActionInput('target', queued);
            await expect(taskActionInputGuard('target', queued)!()).resolves.toBeUndefined();
            return 'accepted';
          },
        );
        expect(result).toBe('accepted');
      }
      expect(h.confirm).not.toHaveBeenCalled();
      expect(hasTaskActionAuthorization('companion')).toBe(false);
      if (kind === 'group') expect(validate).toHaveBeenCalled();
    },
  );

  it.each(['chat', 'tools', 'missing', 'stale', 'other-bot', 'unavailable', 'revoked'] as const)(
    'rejects %s group authority before helper or Orca effects, without prompting',
    async (mode) => {
      const h = desktopFixture();
      if (mode !== 'missing')
        releases.push(
          registerGroupToolAuthority('companion', {
            botId: mode === 'other-bot' ? 'another' : 'bot',
            mode: mode === 'chat' || mode === 'tools' ? mode : 'owner',
            isCurrent: () => mode !== 'stale',
            validate: async () => {
              if (mode === 'unavailable') throw new GroupToolAuthorizationError(true);
              if (mode === 'revoked') throw new GroupToolAuthorizationError();
            },
          }),
        );
      const effect = vi.fn(async () => 'changed');
      for (const [server, tool] of ownerWrites)
        expect(
          await withToolCallAuthority(h.authorize, { ...call(tool), server }, effect),
        ).toMatchObject({ isError: true });
      expect(effect).not.toHaveBeenCalled();
      expect(h.confirm).not.toHaveBeenCalled();
    },
  );

  it('keeps automatic/forwarded input restricted even with an unrelated live group owner grant', async () => {
    const h = desktopFixture('automatic');
    releases.push(
      registerGroupToolAuthority('another-lane', {
        botId: 'bot',
        mode: 'owner',
        isCurrent: () => true,
        validate: async () => {},
      }),
    );
    const effect = vi.fn(async () => 'changed');
    for (const [server, tool] of ownerWrites)
      expect(
        await withToolCallAuthority(h.authorize, { ...call(tool), server }, effect),
      ).toMatchObject({ isError: true });
    expect(
      await withToolCallAuthority(h.authorize, call('get_task_digest'), async () => 'observed'),
    ).toBe('observed');
    expect(effect).not.toHaveBeenCalled();
    expect(h.confirm).not.toHaveBeenCalled();
  });

  it('rechecks owner authority before execution and queued delivery without another confirmation', async () => {
    const h = desktopFixture();
    let live = true;
    releases.push(
      registerGroupToolAuthority('companion', {
        botId: 'bot',
        mode: 'owner',
        isCurrent: () => live,
        validate: async () => {},
      }),
    );
    const queued = input();
    await withToolCallAuthority(h.authorize, call('send_to_session'), async () =>
      bindTaskActionInput('target', queued),
    );
    const decision = await h.authorize(call('start_session_task'));
    if (!decision.ok || !decision.run) throw new Error('missing owner admission');
    live = false;
    const effect = vi.fn(async () => 'started');
    await expect(decision.run(effect)).rejects.toThrow();
    await expect(taskActionInputGuard('target', queued)!()).rejects.toThrow();
    expect(effect).not.toHaveBeenCalled();
    expect(h.confirm).not.toHaveBeenCalled();
  });
});
