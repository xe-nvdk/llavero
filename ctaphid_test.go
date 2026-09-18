package main

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

// recordingHID stands in for uhidDevice. Replies from handlePacket land here
// so the tests can assert on framing without opening /dev/uhid.
type recordingHID struct {
	sent [][]byte
}

func (r *recordingHID) sendInput(report []byte) error {
	r.sent = append(r.sent, bytes.Clone(report))
	return nil
}

func (r *recordingHID) take() [][]byte {
	out := r.sent
	r.sent = nil
	return out
}

func newTestHID(t *testing.T, onCBOR func([]byte) []byte) (*ctapHID, *recordingHID) {
	t.Helper()
	rec := &recordingHID{}
	if onCBOR == nil {
		onCBOR = func([]byte) []byte { return []byte{0x00} }
	}
	h := newCtapHID(rec, onCBOR, func(string, ...any) {})
	h.nextCID = 0xC0FFEE
	return h, rec
}

const testCID = uint32(0x11223344)

// patterned is a payload whose bytes are their own indexes, so an off-by-one
// in reassembly or a swallowed padding byte shows up as a mismatch.
func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// hostFrames splits a host-to-device message into 64-byte CTAPHID packets.
func hostFrames(cid uint32, cmd byte, payload []byte) [][]byte {
	var frames [][]byte
	init := make([]byte, packetSize)
	binary.BigEndian.PutUint32(init[0:4], cid)
	init[4] = cmd | 0x80
	binary.BigEndian.PutUint16(init[5:7], uint16(len(payload)))
	n := len(payload)
	if n > initDataLen {
		n = initDataLen
	}
	copy(init[7:], payload[:n])
	frames = append(frames, init)
	sent := n
	var seq byte
	for sent < len(payload) {
		cont := make([]byte, packetSize)
		binary.BigEndian.PutUint32(cont[0:4], cid)
		cont[4] = seq
		n := len(payload) - sent
		if n > contDataLen {
			n = contDataLen
		}
		copy(cont[5:], payload[sent:sent+n])
		frames = append(frames, cont)
		sent += n
		seq++
	}
	return frames
}

func feed(h *ctapHID, frames ...[]byte) {
	for _, f := range frames {
		h.handlePacket(f)
	}
}

type hidReply struct {
	cid     uint32
	cmd     byte
	payload []byte
}

// collectReply reassembles a device-to-host message and checks that
// continuation packets are numbered 0, 1, 2... on the same channel.
func collectReply(t *testing.T, frames [][]byte) hidReply {
	t.Helper()
	if len(frames) == 0 {
		t.Fatal("no packets were written back")
	}
	first := frames[0]
	if len(first) != packetSize {
		t.Fatalf("init packet is %d bytes, want %d", len(first), packetSize)
	}
	if first[4]&0x80 == 0 {
		t.Fatal("first written packet is a continuation, want an init packet")
	}
	cid := binary.BigEndian.Uint32(first[0:4])
	cmd := first[4] & 0x7F
	bcnt := int(binary.BigEndian.Uint16(first[5:7]))
	n := bcnt
	if n > initDataLen {
		n = initDataLen
	}
	payload := append([]byte{}, first[7:7+n]...)
	for i, f := range frames[1:] {
		if len(f) != packetSize {
			t.Fatalf("continuation %d is %d bytes, want %d", i, len(f), packetSize)
		}
		gotCID := binary.BigEndian.Uint32(f[0:4])
		if gotCID != cid {
			t.Errorf("continuation %d cid = %08x, want %08x", i, gotCID, cid)
		}
		if f[4]&0x80 != 0 {
			t.Fatalf("packet %d is an init packet (cmd 0x%02x), want seq %d", i+1, f[4]&0x7F, i)
		}
		if f[4] != byte(i) {
			t.Errorf("continuation seq = %d, want %d", f[4], i)
		}
		need := bcnt - len(payload)
		chunk := f[5:]
		if len(chunk) > need {
			chunk = chunk[:need]
		}
		payload = append(payload, chunk...)
	}
	if len(payload) != bcnt {
		t.Fatalf("reassembled %d bytes, declared BCNT %d", len(payload), bcnt)
	}
	return hidReply{cid: cid, cmd: cmd, payload: payload}
}

func expectError(t *testing.T, frames [][]byte, cid uint32, code byte) {
	t.Helper()
	reply := collectReply(t, frames)
	if reply.cid != cid {
		t.Errorf("error cid = %08x, want %08x", reply.cid, cid)
	}
	if reply.cmd != cmdError {
		t.Fatalf("cmd = 0x%02x, want ERROR (0x%02x)", reply.cmd, cmdError)
	}
	if !bytes.Equal(reply.payload, []byte{code}) {
		t.Fatalf("error payload %x, want [%02x]", reply.payload, code)
	}
}

func ping(t *testing.T, h *ctapHID, rec *recordingHID, cid uint32, payload []byte) []byte {
	t.Helper()
	feed(h, hostFrames(cid, cmdPing, payload)...)
	reply := collectReply(t, rec.take())
	if reply.cid != cid {
		t.Errorf("pong cid = %08x, want %08x", reply.cid, cid)
	}
	if reply.cmd != cmdPing {
		t.Fatalf("pong cmd = 0x%02x, want PING", reply.cmd)
	}
	if !bytes.Equal(reply.payload, payload) {
		t.Fatalf("pong payload mismatch: got %d bytes, want %d", len(reply.payload), len(payload))
	}
	return reply.payload
}

func TestCTAPHIDPingSinglePacket(t *testing.T) {
	h, rec := newTestHID(t, nil)
	payload := patterned(16)
	feed(h, hostFrames(testCID, cmdPing, payload)...)

	reply := collectReply(t, rec.take())
	if reply.cid != testCID {
		t.Errorf("cid = %08x, want %08x", reply.cid, testCID)
	}
	if reply.cmd != cmdPing {
		t.Errorf("cmd = 0x%02x, want PING", reply.cmd)
	}
	if !bytes.Equal(reply.payload, payload) {
		t.Errorf("echoed %x, want %x", reply.payload, payload)
	}
}

func TestCTAPHIDPingMultiPacket(t *testing.T) {
	// 57 + 59 + 10 needs an init packet and two continuations.
	sizes := []int{58, 57 + 59, 57 + 59 + 10, 200}
	for _, n := range sizes {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			h, rec := newTestHID(t, nil)
			payload := patterned(n)
			frames := hostFrames(testCID, cmdPing, payload)
			if n <= initDataLen && len(frames) != 1 {
				t.Fatalf("host framing of %d bytes used %d packets, want 1", n, len(frames))
			}
			if n > initDataLen && len(frames) < 2 {
				t.Fatalf("host framing of %d bytes used %d packets, want several", n, len(frames))
			}
			feed(h, frames...)
			reply := collectReply(t, rec.take())
			if reply.cmd != cmdPing {
				t.Fatalf("cmd = 0x%02x, want PING", reply.cmd)
			}
			if !bytes.Equal(reply.payload, payload) {
				t.Fatalf("reassembled payload does not match the %d-byte ping", n)
			}
			if _, still := h.pending[testCID]; still {
				t.Error("completed transaction left a pending assembly")
			}
		})
	}
}

func TestCTAPHIDInvalidSequenceDropsTransaction(t *testing.T) {
	h, rec := newTestHID(t, nil)
	payload := patterned(100)
	frames := hostFrames(testCID, cmdPing, payload)
	if len(frames) < 2 {
		t.Fatal("test payload fits in one packet")
	}

	h.handlePacket(frames[0])
	if _, ok := h.pending[testCID]; !ok {
		t.Fatal("init packet did not open a pending transaction")
	}

	bad := bytes.Clone(frames[1])
	bad[4] = 1 // host must send seq 0 first
	h.handlePacket(bad)

	expectError(t, rec.take(), testCID, errInvalidSeq)
	if _, still := h.pending[testCID]; still {
		t.Error("bad sequence left the transaction pending")
	}

	// The original seq-0 continuation is now a continuation on an idle
	// channel and must be ignored, not treated as the start of a reply.
	h.handlePacket(frames[1])
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("stale continuation after ERR_INVALID_SEQ wrote %d packet(s)", len(got))
	}

	// A fresh complete message on the same channel must still work.
	ping(t, h, rec, testCID, patterned(8))
}

func TestCTAPHIDContinuationOnIdleChannelIgnored(t *testing.T) {
	h, rec := newTestHID(t, nil)
	cont := make([]byte, packetSize)
	binary.BigEndian.PutUint32(cont[0:4], testCID)
	cont[4] = 0
	copy(cont[5:], []byte("should-be-ignored"))

	h.handlePacket(cont)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("idle continuation wrote %d packet(s), want silence", len(got))
	}
	if len(h.pending) != 0 {
		t.Error("idle continuation created a pending assembly")
	}
}

func TestCTAPHIDBCNTTooLarge(t *testing.T) {
	h, rec := newTestHID(t, nil)

	over := make([]byte, packetSize)
	binary.BigEndian.PutUint32(over[0:4], testCID)
	over[4] = cmdPing | 0x80
	binary.BigEndian.PutUint16(over[5:7], 7610)
	h.handlePacket(over)
	expectError(t, rec.take(), testCID, errInvalidLen)
	if _, still := h.pending[testCID]; still {
		t.Error("oversize BCNT left a pending assembly")
	}

	// The spec maximum itself is legal; it must not be rejected as invalid.
	max := make([]byte, packetSize)
	binary.BigEndian.PutUint32(max[0:4], testCID)
	max[4] = cmdPing | 0x80
	binary.BigEndian.PutUint16(max[5:7], 7609)
	h.handlePacket(max)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("BCNT=7609 wrote %d packet(s); the message is incomplete, not illegal", len(got))
	}
	if a, ok := h.pending[testCID]; !ok || a.total != 7609 {
		t.Fatal("BCNT=7609 should start a pending transaction")
	}
}

func TestCTAPHIDInitAbortsPending(t *testing.T) {
	h, rec := newTestHID(t, nil)
	otherCID := uint32(0x55667788)

	// Two channels in mid-transaction. INIT on one must not touch the other.
	pingA := hostFrames(testCID, cmdPing, patterned(80))
	pingB := hostFrames(otherCID, cmdPing, patterned(90))
	h.handlePacket(pingA[0])
	h.handlePacket(pingB[0])
	if len(h.pending) != 2 {
		t.Fatalf("pending = %d, want 2", len(h.pending))
	}

	nonce := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	feed(h, hostFrames(testCID, cmdInit, nonce)...)

	if _, still := h.pending[testCID]; still {
		t.Error("CTAPHID_INIT left the aborted transaction pending")
	}
	if _, ok := h.pending[otherCID]; !ok {
		t.Error("CTAPHID_INIT on one channel dropped a transaction on another")
	}

	reply := collectReply(t, rec.take())
	if reply.cmd != cmdInit {
		t.Fatalf("cmd = 0x%02x, want INIT", reply.cmd)
	}
	if reply.cid != testCID {
		t.Errorf("INIT reply cid = %08x, want the requesting channel %08x", reply.cid, testCID)
	}
	if !bytes.Equal(reply.payload[:8], nonce) {
		t.Errorf("INIT nonce = %x, want %x", reply.payload[:8], nonce)
	}
	gotCID := binary.BigEndian.Uint32(reply.payload[8:12])
	if gotCID != testCID {
		t.Errorf("allocated cid = %08x, want the existing channel %08x", gotCID, testCID)
	}

	// Leftover continuation of the aborted ping must be ignored.
	h.handlePacket(pingA[1])
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("continuation of the aborted ping wrote %d packet(s)", len(got))
	}

	// The other channel still completes.
	h.handlePacket(pingB[1])
	pong := collectReply(t, rec.take())
	if pong.cmd != cmdPing || pong.cid != otherCID {
		t.Fatalf("other channel: cmd=0x%02x cid=%08x, want PING on %08x", pong.cmd, pong.cid, otherCID)
	}
	if !bytes.Equal(pong.payload, patterned(90)) {
		t.Error("other channel's ping was corrupted by the abort")
	}
}

func TestCTAPHIDShortFinalPacket(t *testing.T) {
	h, rec := newTestHID(t, nil)

	// A complete ping that the host did not pad to 64 bytes, with junk after
	// BCNT so a sloppy reader that takes the whole remainder would fail.
	payload := []byte{0xAA, 0xBB, 0xCC}
	short := make([]byte, 7+len(payload)+4)
	binary.BigEndian.PutUint32(short[0:4], testCID)
	short[4] = cmdPing | 0x80
	binary.BigEndian.PutUint16(short[5:7], uint16(len(payload)))
	copy(short[7:], payload)
	copy(short[7+len(payload):], []byte{0xFF, 0xFF, 0xFF, 0xFF})
	h.handlePacket(short)

	reply := collectReply(t, rec.take())
	if !bytes.Equal(reply.payload, payload) {
		t.Fatalf("short init echoed %x, want %x (padding must not become payload)", reply.payload, payload)
	}

	// Same thing on the last continuation of a multi-packet message.
	full := patterned(60) // 57 in the init packet, 3 in the continuation
	frames := hostFrames(testCID, cmdPing, full)
	if len(frames) != 2 {
		t.Fatalf("60-byte ping used %d frames, want 2", len(frames))
	}
	h.handlePacket(frames[0])
	cont := frames[1][:5+3] // header + the 3 remaining bytes, no padding
	h.handlePacket(cont)
	reply = collectReply(t, rec.take())
	if !bytes.Equal(reply.payload, full) {
		t.Fatal("short continuation did not reassemble the declared payload")
	}
}

func TestCTAPHIDOutboundFragmentation(t *testing.T) {
	// A large CBOR reply is fragmented independently of how the request arrived.
	payload := patterned(57 + 59 + 20) // three packets: init + seq 0 + seq 1
	h, rec := newTestHID(t, func(req []byte) []byte {
		if !bytes.Equal(req, []byte{0x04}) {
			t.Errorf("onCBOR got %x, want getInfo", req)
		}
		return payload
	})
	feed(h, hostFrames(testCID, cmdCBOR, []byte{0x04})...)

	frames := rec.take()
	if len(frames) != 3 {
		t.Fatalf("wrote %d packets, want 3 (init + two continuations)", len(frames))
	}
	if frames[0][4]&0x80 == 0 || frames[0][4]&0x7F != cmdCBOR {
		t.Fatalf("first packet cmd = 0x%02x, want CBOR init", frames[0][4])
	}
	if frames[1][4] != 0 {
		t.Errorf("first continuation seq = %d, want 0", frames[1][4])
	}
	if frames[2][4] != 1 {
		t.Errorf("second continuation seq = %d, want 1", frames[2][4])
	}
	reply := collectReply(t, frames)
	if !bytes.Equal(reply.payload, payload) {
		t.Fatal("fragmented CBOR reply does not match what onCBOR returned")
	}
}

func TestCTAPHIDRuntPacketDoesNotPanic(t *testing.T) {
	h, rec := newTestHID(t, nil)
	defer func() {
		if recov := recover(); recov != nil {
			t.Fatalf("runt packet panicked: %v", recov)
		}
	}()

	for _, p := range [][]byte{nil, {}, {0x00}, {0x11, 0x22, 0x33, 0x44}} {
		h.handlePacket(p)
	}
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("runt packets wrote %d packet(s)", len(got))
	}

	// Five bytes is the minimum header and must not be treated as a runt.
	// After padding it is an idle continuation (seq 0 on an unused channel).
	min := make([]byte, 5)
	binary.BigEndian.PutUint32(min[0:4], testCID)
	h.handlePacket(min)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("5-byte continuation wrote %d packet(s)", len(got))
	}

	// And a well-formed message still works afterwards.
	ping(t, h, rec, testCID, []byte("ok"))
}

func TestCTAPHIDCancelDropsPending(t *testing.T) {
	h, rec := newTestHID(t, nil)
	frames := hostFrames(testCID, cmdPing, patterned(80))
	h.handlePacket(frames[0])
	feed(h, hostFrames(testCID, cmdCancel, nil)...)
	if _, still := h.pending[testCID]; still {
		t.Error("CANCEL left the transaction pending")
	}
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("CANCEL wrote %d packet(s), want silence", len(got))
	}
	h.handlePacket(frames[1])
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("continuation after CANCEL wrote %d packet(s)", len(got))
	}
}

func TestCTAPHIDBroadcastInitAllocatesChannel(t *testing.T) {
	h, rec := newTestHID(t, nil)
	h.nextCID = 0xFFFFFFFE
	nonce := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	feed(h, hostFrames(broadcastCID, cmdInit, nonce)...)

	reply := collectReply(t, rec.take())
	if reply.cid != broadcastCID {
		t.Errorf("INIT reply travelled on %08x, want the broadcast channel", reply.cid)
	}
	if reply.cmd != cmdInit {
		t.Fatalf("cmd = 0x%02x, want INIT", reply.cmd)
	}
	if !bytes.Equal(reply.payload[:8], nonce) {
		t.Errorf("nonce = %x, want %x", reply.payload[:8], nonce)
	}
	allocated := binary.BigEndian.Uint32(reply.payload[8:12])
	if allocated == 0 || allocated == broadcastCID {
		t.Fatalf("allocated cid %08x is reserved", allocated)
	}
	if reply.payload[12] != 2 {
		t.Errorf("CTAPHID version = %d, want 2", reply.payload[12])
	}
	if reply.payload[16] != capCBOR|capNMSG {
		t.Errorf("caps = 0x%02x, want 0x%02x", reply.payload[16], capCBOR|capNMSG)
	}

	// A second broadcast INIT must not hand out 0xFFFFFFFF after wrapping.
	feed(h, hostFrames(broadcastCID, cmdInit, nonce)...)
	second := binary.BigEndian.Uint32(collectReply(t, rec.take()).payload[8:12])
	if second == 0 || second == broadcastCID || second == allocated {
		t.Fatalf("wrapped allocation produced cid %08x", second)
	}
}

func TestCTAPHIDEmptyCBORIsInvalidLen(t *testing.T) {
	h, rec := newTestHID(t, nil)
	feed(h, hostFrames(testCID, cmdCBOR, nil)...)
	expectError(t, rec.take(), testCID, errInvalidLen)
}

func TestCTAPHIDMsgIsRefused(t *testing.T) {
	h, rec := newTestHID(t, nil)
	feed(h, hostFrames(testCID, cmdMsg, []byte{0x00})...)
	expectError(t, rec.take(), testCID, errInvalidCmd)
}

func TestCTAPHIDUnknownCommand(t *testing.T) {
	h, rec := newTestHID(t, nil)
	feed(h, hostFrames(testCID, 0x2A, []byte{0x00})...)
	expectError(t, rec.take(), testCID, errInvalidCmd)
}

func TestCTAPHIDWink(t *testing.T) {
	h, rec := newTestHID(t, nil)
	feed(h, hostFrames(testCID, cmdWink, nil)...)
	reply := collectReply(t, rec.take())
	if reply.cmd != cmdWink || len(reply.payload) != 0 {
		t.Fatalf("wink cmd=0x%02x payload=%x, want empty WINK", reply.cmd, reply.payload)
	}
}

func TestCTAPHIDCBORReassembly(t *testing.T) {
	want := patterned(130)
	var got []byte
	h, rec := newTestHID(t, func(payload []byte) []byte {
		got = bytes.Clone(payload)
		return []byte{0x00, 0xA0}
	})
	feed(h, hostFrames(testCID, cmdCBOR, want)...)
	if !bytes.Equal(got, want) {
		t.Fatalf("onCBOR received %d bytes, want %d; inbound reassembly lost data", len(got), len(want))
	}
	reply := collectReply(t, rec.take())
	if reply.cmd != cmdCBOR || !bytes.Equal(reply.payload, []byte{0x00, 0xA0}) {
		t.Fatalf("CBOR reply cmd=0x%02x payload=%x", reply.cmd, reply.payload)
	}
}
