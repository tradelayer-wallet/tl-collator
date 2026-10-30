// Stand-in for the native `wrtc` package in e2e runs that drive a DataChannel (TL_E2E_WRTC=fake).
// Each peer connection opens one channel as soon as the offer is set. The collator's outgoing
// messages reach the test as SIGNAL_ICE candidates "out:<json>"; the test's messages reach the
// collator as candidates "in:<json>". Both directions cross the real signalling socket.
class FakeRTCPeerConnection {
  constructor() {
    this.ondatachannel = null;
    this.onicecandidate = null;
    this.channel = null;
  }

  async setRemoteDescription() {
    this.openChannel();
  }

  // Opens one more channel on this connection, as a peer does when it opens its channel again.
  openChannel() {
    const pc = this;
    this.channel = {
      readyState: 'open',
      bufferedAmount: 0,
      onmessage: null,
      onclose: null,
      send(data) {
        pc.emit(`out:${data}`);
      },
      close() {
        if (this.readyState === 'closed') return;
        this.readyState = 'closed';
        pc.emit('closed');
        queueMicrotask(() => this.onclose?.());
      },
    };
    this.ondatachannel({ channel: this.channel });
  }

  async createAnswer() {
    return { type: 'answer', sdp: 'fake-answer' };
  }

  async setLocalDescription() {}

  async addIceCandidate(candidate) {
    const text = candidate?.candidate ?? '';
    if (text === 'open') {
      this.openChannel();
      return;
    }
    if (text.startsWith('in:') && this.channel?.readyState === 'open') {
      this.channel.onmessage({ data: text.slice(3) });
    }
  }

  emit(text) {
    if (!this.onicecandidate) return;
    this.onicecandidate({ candidate: { toJSON: () => ({ candidate: text }) } });
  }

  close() {}
}

export default { RTCPeerConnection: FakeRTCPeerConnection };
