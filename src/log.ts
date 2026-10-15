// Internal error detail goes to the log only. Peer-facing responses carry fixed text.
export function logInternalError(event: string, e: unknown): void {
  const msg = e instanceof Error ? e.message : String(e);
  console.error(JSON.stringify({ service: 'tl-collator', event, msg }));
}
