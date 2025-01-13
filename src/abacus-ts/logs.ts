import { log, logInfo } from '@/lib/telemetry';

export function logAbacusTsError(source: string, message: string, ...args: any[]) {
  log(`bonsai: ${source}: ${message}`, undefined, { context: args });
}

export function logAbacusTsInfo(source: string, message: string, ...args: any[]) {
  logInfo(`bonsai: ${source}: ${message}`, { context: args });
}
