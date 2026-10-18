import { and, eq } from 'drizzle-orm';
import type { ToolCallAuthorizer } from '@cindy/mcps';
import { botDelegations, botProfiles, botSessionLinks, sessions } from '../localDb/schema.js';
import { tryGetDbClient } from '../localDb/client/current.js';
import { isAppSessionBoundaryPending } from '../appSessionState.js';
import { readActiveFollowUpRoutine } from '../routines/service.js';
import { createTaskActionAuthorizer, DELEGATED_TASK_ACTIONS } from './taskActionAuthorization.js';

/** Adapt the shared gate to Host facts. No transcript parsing or Agent-supplied approval fields. */
export function createDesktopTaskActionAuthorizer(deps: {
  input(sessionId: string): { key: string; ownerInput: boolean; automatic?: boolean; boundary: string };
  confirm(sessionId: string, tool: string, args: unknown): Promise<boolean>;
}): ToolCallAuthorizer {
  return createTaskActionAuthorizer({
    confirm: deps.confirm,
    capture: async (call) => {
      if (!call.sessionId) throw new Error('TASK_UNAVAILABLE');
      const sessionId = call.sessionId;
      const db = tryGetDbClient();
      if (!db || isAppSessionBoundaryPending()) throw new Error('HOST_NOT_READY');
      const [caller] = await db.drizzle.select({ source: sessions.source, clearedAt: sessions.clearedAt,
        botId: botSessionLinks.botId, botStatus: botProfiles.status, archivedAt: botSessionLinks.archivedAt,
      }).from(sessions).leftJoin(botSessionLinks, eq(botSessionLinks.sessionId, sessions.id))
        .leftJoin(botProfiles, eq(botProfiles.id, botSessionLinks.botId)).where(eq(sessions.id, sessionId)).limit(1);
      if (!caller) throw new Error('TASK_UNAVAILABLE');
      const input = deps.input(sessionId);
      // User-authored ordinary work retains the existing Agent permission flow.
      if (!caller.botId && caller.source !== 'bot' && caller.source !== 'scheduler' && !input.automatic) return null;
      if (caller.botId && (caller.botStatus !== 'active' || caller.archivedAt !== null)) throw new Error('BOT_SESSION_INACTIVE');
      const args = call.args && typeof call.args === 'object' && !Array.isArray(call.args)
        ? call.args as Record<string, unknown> : {};
      const taskId = typeof args.task_id === 'string' ? args.task_id : undefined;
      const readDelegation = async () => {
        if (!taskId || !DELEGATED_TASK_ACTIONS.includes(call.tool as typeof DELEGATED_TASK_ACTIONS[number])) return null;
        const [row] = await db.drizzle.select().from(botDelegations)
          .where(and(eq(botDelegations.id, taskId), eq(botDelegations.parentSessionId, sessionId))).limit(1);
        if (!row || !['queued', 'running', 'waiting'].includes(row.status)) return null;
        let snapshot: { taskActionAuthority?: { version?: number; actions?: string[] }; taskPause?: unknown };
        try { snapshot = JSON.parse(row.permissionSnapshotJson); } catch { return null; }
        const grant = snapshot.taskActionAuthority;
        // Paused work only resumes following a new owner confirmation. Permission answers
        // and model changes are also exact decisions, never a standing message grant.
        if (snapshot.taskPause || args.decision || args.answers || args.mode === 'resume') return null;
        return grant?.version === 1 && grant.actions?.includes(call.tool) ? row : null;
      };
      const delegation = await readDelegation();
      const routine = !input.ownerInput && caller.botId ? readActiveFollowUpRoutine(caller.botId) : null;
      const assertDeliveryCurrent = async () => {
        if (isAppSessionBoundaryPending() || db !== tryGetDbClient()
          || deps.input(sessionId).boundary !== input.boundary) throw new Error('TASK_ACTION_AUTHORIZATION_EXPIRED');
        const [fresh] = await db.drizzle.select({ status: sessions.status, clearedAt: sessions.clearedAt,
          botStatus: botProfiles.status, archivedAt: botSessionLinks.archivedAt,
        }).from(sessions).leftJoin(botSessionLinks, eq(botSessionLinks.sessionId, sessions.id))
          .leftJoin(botProfiles, eq(botProfiles.id, botSessionLinks.botId)).where(eq(sessions.id, sessionId)).limit(1);
        if (!fresh || fresh.status === 'deleted' || fresh.clearedAt !== caller.clearedAt
          || (caller.botId && (fresh.botStatus !== 'active' || fresh.archivedAt !== null))) throw new Error('TASK_ACTION_AUTHORIZATION_EXPIRED');
        if (delegation) {
          const current = await readDelegation();
          if (!current || current.runSequence !== delegation.runSequence) throw new Error('TASK_ACTION_AUTHORIZATION_EXPIRED');
        }
        if (!input.ownerInput && caller.botId) {
          const current = readActiveFollowUpRoutine(caller.botId);
          if (!routine?.enabled || !current?.enabled || current.revision !== routine.revision)
            throw new Error('TASK_ACTION_AUTHORIZATION_EXPIRED');
        }
        if (db !== tryGetDbClient() || isAppSessionBoundaryPending()) throw new Error('OWNER_SCOPE_CHANGED');
      };
      return { key: input.key, ownerInput: input.ownerInput, delegated: !!delegation,
        assertDeliveryCurrent,
        assertCurrent: async () => {
          await assertDeliveryCurrent();
          if (deps.input(sessionId).key !== input.key) throw new Error('TASK_ACTION_AUTHORIZATION_EXPIRED');
        } };
    },
  });
}
