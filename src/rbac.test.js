import { describe, expect, it } from 'vitest';
import { ACTION_RULES, extractActorRoles, requireRole } from './index.js';

describe('RBAC rules', () => {
  it('normalizes multi-role strings into canonical role labels', () => {
    const roles = extractActorRoles('协调者·主属性, 执行者·第二属性');
    expect(roles).toContain('协调者');
    expect(roles).toContain('执行者');
  });

  it('rejects missing payload with 401', () => {
    const result = requireRole(null, ['协调者'], 'dispatches:POST');
    expect(result.ok).toBe(false);
    expect(result.status).toBe(401);
  });

  it('dispatches POST allows coordinator and denies executor', () => {
    const allowed = requireRole({ role: '协调者' }, ACTION_RULES.dispatches.POST, 'dispatches:POST');
    const denied = requireRole({ role: '执行者' }, ACTION_RULES.dispatches.POST, 'dispatches:POST');
    expect(allowed.ok).toBe(true);
    expect(denied.ok).toBe(false);
    expect(denied.status).toBe(403);
  });

  it('tasks POST allows planner and denies driver', () => {
    const allowed = requireRole({ role: '统筹者' }, ACTION_RULES.tasks.POST, 'tasks:POST');
    const denied = requireRole({ role: '推进者' }, ACTION_RULES.tasks.POST, 'tasks:POST');
    expect(allowed.ok).toBe(true);
    expect(denied.ok).toBe(false);
    expect(denied.status).toBe(403);
  });

  it('blockages PATCH allows breaker and denies executor', () => {
    const allowed = requireRole({ role: '破局者' }, ACTION_RULES.blockages.PATCH, 'blockages:PATCH');
    const denied = requireRole({ role: '执行者' }, ACTION_RULES.blockages.PATCH, 'blockages:PATCH');
    expect(allowed.ok).toBe(true);
    expect(denied.ok).toBe(false);
    expect(denied.status).toBe(403);
  });

  it('notify can be called by authenticated known roles', () => {
    const allowed = requireRole({ role: '技术支持者' }, ['协调者', '统筹者', '推进者', '执行者', '破局者', '技术支持者'], 'notify:POST');
    expect(allowed.ok).toBe(true);
  });
});
