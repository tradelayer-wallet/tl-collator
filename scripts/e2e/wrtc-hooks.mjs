// Module resolve hook for e2e runs only: `wrtc` ships a native WebRTC binding
// that is not available on every platform. The HTTP and WebSocket paths under
// test never create a peer connection, so a stub is sufficient there.
export async function resolve(specifier, context, next) {
  if (specifier === 'wrtc') {
    return { url: new URL('./wrtc-stub.mjs', import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
