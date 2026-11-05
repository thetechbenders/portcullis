// Package ipc defines the local control protocol between the unprivileged
// portal, the operator tooling and the privileged portcullisd controller.
//
// Guest operations are only accepted on the guest socket and must carry the
// guest's live TCP connection to the portal as an SCM_RIGHTS descriptor. The
// controller derives the guest address from that kernel socket, never from
// request fields, cookies, headers or any other browser-supplied value.
package ipc

import (
	"context"
	"net/netip"
	"time"
)

// MaxMessageBytes bounds every request on the control sockets.
const MaxMessageBytes = 16 << 10

// MaxResponseBytes bounds every response. Operator snapshots list up to the
// kernel set size of bindings and grants plus the bounded event ring, so they
// need more room than requests do.
const MaxResponseBytes = 1 << 20

// Peer is the kernel-reported credential of a control socket client
// (SO_PEERCRED), never a value supplied in the request.
type Peer struct {
	UID uint32
	GID uint32
	PID int32
}

// GuestConn is the controller's own view of the guest TCP connection that
// the portal passed over SCM_RIGHTS: both endpoints come from getsockname
// and getpeername on the received descriptor.
type GuestConn struct {
	Local  netip.AddrPort
	Remote netip.AddrPort
}

// Handler serves one validated control request. guest is non-nil only on
// the guest socket, after descriptor validation succeeded.
type Handler interface {
	Handle(ctx context.Context, peer Peer, req Request, guest *GuestConn) Response
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, peer Peer, req Request, guest *GuestConn) Response

// Handle calls f.
func (f HandlerFunc) Handle(ctx context.Context, peer Peer, req Request, guest *GuestConn) Response {
	return f(ctx, peer, req, guest)
}

// Op names one control operation.
type Op string

const (
	// Guest operations: guest socket only, connection descriptor required.
	OpStatus  Op = "status"
	OpRequest Op = "request"
	OpRelease Op = "release"

	// Operator operations: operator socket only, no descriptor accepted.
	OpSnapshot Op = "snapshot"
	OpRevoke   Op = "revoke"
	OpReset    Op = "reset"
)

// Request is a single control request. It deliberately has no field that
// can name a guest address or client identity for guest operations.
type Request struct {
	Op Op `json:"op"`
	// DurationSeconds is the requested grant length for OpRequest. Zero
	// selects the configured default. The controller clamps nothing: values
	// outside the configured bounds are rejected.
	DurationSeconds int `json:"duration_seconds,omitempty"`
	// Target is the MAC address (canonical colon form) for OpRevoke.
	Target string `json:"target,omitempty"`
}

// State is the guest-visible authorization state. It always reflects
// effective kernel state, never a pending or merely requested grant.
type State string

const (
	// StateUnrecognized: no live Portcullis DHCP binding for the observed
	// connection address.
	StateUnrecognized State = "unrecognized"
	// StateAmbiguous: attachment evidence conflicts (for example the kernel
	// neighbour entry disagrees with the DHCP binding). Nothing is granted.
	StateAmbiguous State = "ambiguous"
	// StateDenied: recognized client without an effective grant.
	StateDenied State = "denied"
	// StateGranted: the kernel grant elements are present and unexpired.
	StateGranted State = "granted"
	// StateRevoked: an operator revocation cooldown is active.
	StateRevoked State = "revoked"
	// StateUnavailable: enforcement is degraded or unverified, so the
	// controller refuses to grant anything.
	StateUnavailable State = "unavailable"
)

// Session describes one guest's authorization as the controller sees it.
type Session struct {
	State  State  `json:"state"`
	Reason string `json:"reason"`
	// ClientAddress is the kernel-observed IPv4 address of the connection.
	ClientAddress string `json:"client_address,omitempty"`
	// ClientMACHint lets a person recognize their device; never a full MAC.
	ClientMACHint string `json:"client_mac_hint,omitempty"`
	// RemainingSeconds is read back from the kernel grant element.
	RemainingSeconds int `json:"remaining_seconds,omitempty"`
	// GrantedSeconds is the total length of the current grant.
	GrantedSeconds int `json:"granted_seconds,omitempty"`
	// RetryAfterSeconds is set while rate limiting or revocation applies.
	RetryAfterSeconds      int  `json:"retry_after_seconds,omitempty"`
	CanRequest             bool `json:"can_request"`
	DefaultDurationSeconds int  `json:"default_duration_seconds"`
	MaxDurationSeconds     int  `json:"max_duration_seconds"`
}

// ErrorCode is a stable machine-readable failure class.
type ErrorCode string

const (
	ErrBadRequest  ErrorCode = "bad_request"
	ErrForbidden   ErrorCode = "forbidden"
	ErrIdentity    ErrorCode = "identity"
	ErrConflict    ErrorCode = "conflict"
	ErrRateLimited ErrorCode = "rate_limited"
	ErrUnavailable ErrorCode = "unavailable"
	ErrInternal    ErrorCode = "internal"
)

// Response is a single control response. Session is populated for guest
// operations even on failure whenever the controller can describe the
// guest's current state.
type Response struct {
	OK       bool      `json:"ok"`
	Error    ErrorCode `json:"error,omitempty"`
	Message  string    `json:"message,omitempty"`
	Session  *Session  `json:"session,omitempty"`
	Snapshot *Snapshot `json:"snapshot,omitempty"`
}

// Snapshot is the operator diagnostic view. It must never be served on a
// guest-reachable listener.
type Snapshot struct {
	GeneratedAt     time.Time     `json:"generated_at"`
	Enforcement     string        `json:"enforcement"` // "ok" or "degraded"
	Isolation       string        `json:"isolation"`   // "not_required", "confirmed", "unconfirmed"
	DegradedReason  string        `json:"degraded_reason,omitempty"`
	LastAttestation time.Time     `json:"last_attestation"`
	Bindings        []BindingView `json:"bindings"`
	Grants          []GrantView   `json:"grants"`
	Counters        []CounterView `json:"counters"`
	Events          []EventView   `json:"events"`
}

// BindingView is one DHCP binding with its derived authorization state.
type BindingView struct {
	Address               string `json:"address"`
	MAC                   string `json:"mac"`
	LeaseRemainingSeconds int    `json:"lease_remaining_seconds"`
	State                 State  `json:"state"`
	RevokedForSeconds     int    `json:"revoked_for_seconds,omitempty"`
}

// GrantView contrasts the controller's desired grant with kernel state.
type GrantView struct {
	Address                 string `json:"address"`
	MAC                     string `json:"mac"`
	GrantedSeconds          int    `json:"granted_seconds"`
	DesiredRemainingSeconds int    `json:"desired_remaining_seconds"`
	KernelPresent           bool   `json:"kernel_present"`
	KernelRemainingSeconds  int    `json:"kernel_remaining_seconds"`
}

// CounterView is one labelled kernel rule counter.
type CounterView struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// EventView is one entry from the controller's bounded audit ring. Details
// never contain bearer secrets.
type EventView struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}
