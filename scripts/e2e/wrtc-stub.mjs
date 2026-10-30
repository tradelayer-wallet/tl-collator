// Stand-in for the native `wrtc` package in e2e runs (see wrtc-hooks.mjs).
// Using WebRTC (SIGNAL_OFFER) under this stub fails loudly.
class UnavailableRTCPeerConnection {
  constructor() {
    throw new Error('wrtc stub: WebRTC is not available in e2e runs');
  }
}

export default { RTCPeerConnection: UnavailableRTCPeerConnection };
