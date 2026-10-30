// Module resolve hook for e2e runs only: `wrtc` ships a native WebRTC binding
// that is not available on every platform. The HTTP and WebSocket paths under
// test never create a peer connection, so a stub is sufficient there. Tests
// that drive a DataChannel set TL_E2E_WRTC=fake (see wrtc-fake.mjs).
export async function resolve(specifier, context, next) {
  if (specifier === 'wrtc') {
    const file = process.env.TL_E2E_WRTC === 'fake' ? 'wrtc-fake.mjs' : 'wrtc-stub.mjs';
    return { url: new URL(`./${file}`, import.meta.url).href, shortCircuit: true };
  }
  return next(specifier, context);
}
