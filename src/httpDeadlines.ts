import type { EventEmitter } from 'node:events';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Socket } from 'node:net';
import tls from 'node:tls';

/**
 * Per-connection request deadlines (round 8, slowloris; corrected in round 10), the same policy as tl-relayer.
 *
 * Node's own `headersTimeout` and `requestTimeout` did not close stalled connections on the
 * runtime targeted here (Node 24.20): the connections expiry check kept returning zero for a
 * partial header block. Socket inactivity is defeated by a slow drip. This watchdog is the
 * enforcement point for the request phase:
 *
 * - a new connection must deliver its request headers within HEADERS_DEADLINE_MS;
 * - once the headers of a request that carries a body are in, the body must be complete within
 *   BODY_DEADLINE_MS. A bodyless request (GET, HEAD, DELETE with no Content-Length) has no body
 *   phase, because Node emits 'end' for an unread body only when the response finishes;
 * - when no request is in flight after a response finishes, an idle keep-alive socket is closed
 *   after KEEP_ALIVE_IDLE_MS;
 * - an upgraded socket (the WebSocket session) leaves HTTP tracking, so no deadline applies.
 *
 * TLS: the request runs on the TLSSocket from 'secureConnection', so the timers attach there.
 * The raw TCP socket is not timed, because a timer on it would also close a live TLS session.
 * The TLS handshake is bounded by the server option `handshakeTimeout` (see index.ts).
 * Handler time is not covered here; the handlers bound their own outbound calls.
 */
export const HEADERS_DEADLINE_MS = 10_000;
export const BODY_DEADLINE_MS = 30_000;
export const KEEP_ALIVE_IDLE_MS = 60_000;

export interface RequestDeadlines {
  headersMs: number;
  bodyMs: number;
  idleMs: number;
}

export const DEFAULT_REQUEST_DEADLINES: RequestDeadlines = {
  headersMs: HEADERS_DEADLINE_MS,
  bodyMs: BODY_DEADLINE_MS,
  idleMs: KEEP_ALIVE_IDLE_MS,
};

type Timer = ReturnType<typeof setTimeout>;
type SocketState = { timer: Timer | null; inFlight: number };

const states = new WeakMap<Socket, SocketState>();

const stateOf = (socket: Socket): SocketState => {
  let state = states.get(socket);
  if (!state) {
    state = { timer: null, inFlight: 0 };
    states.set(socket, state);
  }
  return state;
};

const clearTimer = (state: SocketState): void => {
  if (state.timer !== null) {
    clearTimeout(state.timer);
    state.timer = null;
  }
};

// Replaces the socket's deadline and returns the new timer, so the owner can clear it later.
const armTimer = (socket: Socket, state: SocketState, ms: number): Timer => {
  clearTimer(state);
  const timer: Timer = setTimeout(() => {
    if (state.timer === timer) state.timer = null;
    socket.destroy();
  }, ms);
  state.timer = timer;
  return timer;
};

const declaresBody = (req: IncomingMessage): boolean =>
  req.headers['transfer-encoding'] !== undefined || Number(req.headers['content-length'] ?? 0) > 0;

export function attachRequestDeadlines(
  server: EventEmitter,
  deadlines: RequestDeadlines = DEFAULT_REQUEST_DEADLINES,
): void {
  const onSocket = (socket: Socket): void => {
    const state = stateOf(socket);
    armTimer(socket, state, deadlines.headersMs);
    socket.once('close', () => clearTimer(state));
  };
  server.on(server instanceof tls.Server ? 'secureConnection' : 'connection', onSocket);

  server.on('request', (req: IncomingMessage, res: ServerResponse) => {
    const socket = req.socket;
    const state = stateOf(socket);
    clearTimer(state);
    state.inFlight += 1;
    if (!req.complete && declaresBody(req)) {
      const bodyTimer = armTimer(socket, state, deadlines.bodyMs);
      req.once('end', () => {
        if (state.timer === bodyTimer) clearTimer(state);
      });
    }
    res.once('finish', () => {
      state.inFlight = Math.max(0, state.inFlight - 1);
      if (state.inFlight === 0 && !socket.destroyed) armTimer(socket, state, deadlines.idleMs);
    });
  });

  // The WebSocket session owns upgraded sockets. Their idle and lifetime rules are not HTTP ones.
  server.on('upgrade', (_req: IncomingMessage, socket: Socket) => {
    clearTimer(stateOf(socket));
  });
}
