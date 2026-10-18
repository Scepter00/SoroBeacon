// Package grpc_test exercises the gRPC server's auth interceptors, service
// handlers, alert stream, and server lifecycle. Tests run against an in-process
// bufconn listener — no network, no port allocation — so they are hermetic and
// do not require a running database.
//
// Issue #440 is covered by the auth interceptor suite below: every method in
// the service descriptor is swept for authentication enforcement, so a method
// added later without a guard fails this test.
package grpc

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/sorotrail/sorobeacon/internal/auth"
	"github.com/sorotrail/sorobeacon/internal/store"
	"github.com/sorotrail/sorobeacon/internal/workspace"
)

// bufSize is the in-memory buffer size for the bufconn listener.
const bufSize = 1 << 20 // 1 MiB

// --- helpers ---

// newTestSQLiteStore creates a fresh SQLite store backed by a temp-dir file
// with all migrations applied. It registers a cleanup function so the caller
// does not have to.
func newTestSQLiteStore(t *testing.T) store.Store {
	t.Helper()
	url := "sqlite://" + filepath.Join(t.TempDir(), "test.db")
	require.NoError(t, store.Migrate(url))
	st, err := store.New(context.Background(), url, store.PoolSettings{}, nil)
	require.NoError(t, err)
	t.Cleanup(st.Close)
	return st
}

// startServer starts an in-process gRPC server backed by the given store and
// authenticator. It returns a client connection and a cancel function that
// shuts the server down cleanly.
func startServer(t *testing.T, st store.Store, authn *auth.Authenticator) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := New(st, authn, nil)
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		select {
		case <-errCh:
		case <-time.After(5 * time.Second):
			t.Error("gRPC server did not stop in time")
		}
	})
	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithDefaultCallOptions(grpc.CallContentSubtype("json")),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// callAllMethods invokes every registered RPC method (unary and streaming) on
// the given connection, using the supplied metadata. It returns one error per
// method in the same order as monitorServiceDesc.Methods / .Streams.
func callAllMethods(ctx context.Context, conn *grpc.ClientConn) []error {
	var errs []error

	// Unary methods — GetMonitor, ListMonitors, ListAlerts.
	for _, m := range monitorServiceDesc.Methods {
		var reply interface{}
		err := conn.Invoke(ctx,
			"/"+monitorServiceDesc.ServiceName+"/"+m.MethodName,
			&GetMonitorRequest{}, &reply)
		errs = append(errs, err)
	}

	// Streaming methods — StreamAlerts.
	for _, s := range monitorServiceDesc.Streams {
		stream, err := conn.NewStream(ctx,
			&grpc.StreamDesc{ServerStreams: s.ServerStreams},
			"/"+monitorServiceDesc.ServiceName+"/"+s.StreamName)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		// Send the empty request and receive the first message (or the error).
		_ = stream.SendMsg(&StreamAlertsRequest{})
		var msg AlertProto
		errs = append(errs, stream.RecvMsg(&msg))
	}
	return errs
}

// metaCtx attaches a bearer token to ctx as gRPC incoming metadata, matching
// how a real client sends the Authorization header.
func metaCtx(ctx context.Context, token string) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + token,
	})
	return metadata.NewOutgoingContext(ctx, md)
}

// --- #440: auth interceptors ---

// TestAuthInterceptors_EveryMethodRejectsUnauthenticated is the most important
// test in this file: it drives every registered method through the interceptors
// without a credential and asserts that each one returns Unauthenticated. A
// method added to the service descriptor without an interceptor guard would
// return a different code and fail this assertion — exactly as the HTTP
// route-scope guard does for the REST surface.
func TestAuthInterceptors_EveryMethodRejectsUnauthenticated(t *testing.T) {
	authn := auth.New([]string{"secret"}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	errs := callAllMethods(context.Background(), conn)

	totalMethods := len(monitorServiceDesc.Methods) + len(monitorServiceDesc.Streams)
	require.Len(t, errs, totalMethods,
		"expected one error per registered method; the test helper must be updated when the descriptor changes")

	for i, err := range errs {
		require.Error(t, err, "method %d returned no error without a credential", i)
		code := status.Code(err)
		assert.Equal(t, codes.Unauthenticated, code,
			"method %d: want Unauthenticated, got %s", i, code)
	}
}

// TestAuthInterceptors_MissingCredential asserts the status code (not just the
// presence of an error) for both the unary and streaming paths.
func TestAuthInterceptors_MissingCredential(t *testing.T) {
	authn := auth.New([]string{"secret"}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	t.Run("unary", func(t *testing.T) {
		var reply interface{}
		err := conn.Invoke(context.Background(),
			"/sorobeacon.v1.MonitorService/GetMonitor",
			&GetMonitorRequest{ID: 1}, &reply)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err),
			"missing credential must yield Unauthenticated, not %s", status.Code(err))
	})

	t.Run("stream", func(t *testing.T) {
		stream, err := conn.NewStream(context.Background(),
			&grpc.StreamDesc{ServerStreams: true},
			"/sorobeacon.v1.MonitorService/StreamAlerts")
		require.NoError(t, err)
		_ = stream.SendMsg(&StreamAlertsRequest{})
		var msg AlertProto
		err = stream.RecvMsg(&msg)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err),
			"missing credential on stream must yield Unauthenticated, not %s", status.Code(err))
	})
}

// TestAuthInterceptors_InvalidToken verifies that a syntactically wrong
// credential — one that fails Bearer parsing — is rejected as Unauthenticated
// on both paths.
func TestAuthInterceptors_InvalidToken(t *testing.T) {
	authn := auth.New([]string{"secret"}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	// A header without the "Bearer " scheme prefix is malformed.
	badCtx := func() context.Context {
		md := metadata.New(map[string]string{"authorization": "not-bearer"})
		return metadata.NewOutgoingContext(context.Background(), md)
	}

	t.Run("unary", func(t *testing.T) {
		var reply interface{}
		err := conn.Invoke(badCtx(),
			"/sorobeacon.v1.MonitorService/GetMonitor",
			&GetMonitorRequest{ID: 1}, &reply)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("stream", func(t *testing.T) {
		stream, err := conn.NewStream(badCtx(),
			&grpc.StreamDesc{ServerStreams: true},
			"/sorobeacon.v1.MonitorService/StreamAlerts")
		require.NoError(t, err)
		_ = stream.SendMsg(&StreamAlertsRequest{})
		var msg AlertProto
		err = stream.RecvMsg(&msg)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

// TestAuthInterceptors_WrongToken verifies that a token that is syntactically
// correct but does not match the configured secret is rejected. This is the
// "revoked or unknown" case that the issue calls out as important.
func TestAuthInterceptors_WrongToken(t *testing.T) {
	authn := auth.New([]string{"real-secret"}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	wrongCtx := metaCtx(context.Background(), "wrong-token")

	t.Run("unary", func(t *testing.T) {
		var reply interface{}
		err := conn.Invoke(wrongCtx,
			"/sorobeacon.v1.MonitorService/GetMonitor",
			&GetMonitorRequest{ID: 1}, &reply)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("stream", func(t *testing.T) {
		stream, err := conn.NewStream(wrongCtx,
			&grpc.StreamDesc{ServerStreams: true},
			"/sorobeacon.v1.MonitorService/StreamAlerts")
		require.NoError(t, err)
		_ = stream.SendMsg(&StreamAlertsRequest{})
		var msg AlertProto
		err = stream.RecvMsg(&msg)
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})
}

// TestAuthInterceptors_ValidToken verifies that a correct token is accepted
// on both the unary and streaming paths.
func TestAuthInterceptors_ValidToken(t *testing.T) {
	authn := auth.New([]string{"my-token"}, 0)
	st := newTestSQLiteStore(t)

	// Seed a monitor so GetMonitor returns something meaningful.
	ctx := workspace.With(context.Background(), workspace.Default)
	m := &store.Monitor{Name: "canary", ContractIDs: []string{"C1"}, Enabled: true}
	require.NoError(t, st.CreateMonitor(ctx, m))

	conn := startServer(t, st, authn)
	authCtx := metaCtx(context.Background(), "my-token")

	t.Run("unary GetMonitor accepted", func(t *testing.T) {
		var reply MonitorProto
		err := conn.Invoke(authCtx,
			"/sorobeacon.v1.MonitorService/GetMonitor",
			&GetMonitorRequest{ID: m.ID}, &reply)
		// NotFound is fine — it means the interceptor passed and the handler ran.
		if err != nil {
			assert.NotEqual(t, codes.Unauthenticated, status.Code(err),
				"valid token must not yield Unauthenticated; got %s", status.Code(err))
		}
	})

	t.Run("stream accepted", func(t *testing.T) {
		sCtx, cancel := context.WithTimeout(authCtx, 200*time.Millisecond)
		defer cancel()
		stream, err := conn.NewStream(sCtx,
			&grpc.StreamDesc{ServerStreams: true},
			"/sorobeacon.v1.MonitorService/StreamAlerts")
		require.NoError(t, err)
		_ = stream.SendMsg(&StreamAlertsRequest{})
		var msg AlertProto
		err = stream.RecvMsg(&msg)
		// DeadlineExceeded or io.EOF are fine — the server accepted the stream.
		// Unauthenticated is not.
		if err != nil {
			code := status.Code(err)
			assert.NotEqual(t, codes.Unauthenticated, code,
				"valid token must not yield Unauthenticated on stream; got %s", code)
		}
	})
}

// TestAuthInterceptors_NoAuthConfigured asserts that when auth is disabled
// (nil authenticator) every method is reachable without a credential.
func TestAuthInterceptors_NoAuthConfigured(t *testing.T) {
	st := newTestSQLiteStore(t)
	conn := startServer(t, st, nil) // nil disables auth

	var reply interface{}
	err := conn.Invoke(context.Background(),
		"/sorobeacon.v1.MonitorService/ListMonitors",
		&ListMonitorsRequest{Limit: 10}, &reply)
	// Any non-Unauthenticated result (including nil) means the call got through.
	if err != nil {
		assert.NotEqual(t, codes.Unauthenticated, status.Code(err),
			"disabled auth must not block the call; got %s", status.Code(err))
	}
}

// TestAuthInterceptors_CredentialNotEchoedInError confirms that no credential
// value appears in the error message or status detail. Echoing a bearer token
// in an error message would expose it to callers and logs.
func TestAuthInterceptors_CredentialNotEchoedInError(t *testing.T) {
	const secret = "super-secret-token-value"
	authn := auth.New([]string{secret}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	// Send a wrong token and check that the secret does not appear in the error.
	wrongCtx := metaCtx(context.Background(), "wrong-"+secret)
	var reply interface{}
	err := conn.Invoke(wrongCtx,
		"/sorobeacon.v1.MonitorService/GetMonitor",
		&GetMonitorRequest{ID: 1}, &reply)
	require.Error(t, err)
	errMsg := err.Error()
	assert.NotContains(t, errMsg, secret,
		"the correct secret value must not appear in the error message")
	assert.NotContains(t, errMsg, "wrong-"+secret,
		"the submitted token must not be echoed back in the error message")
}

// TestAuthInterceptors_ServiceDescriptorCoverage is the sweep that the issue
// labels "the most valuable part": it confirms that every method and stream in
// the service descriptor receives an Unauthenticated rejection when no
// credential is supplied, so a method added later without an interceptor
// guard fails here rather than silently escaping authentication.
func TestAuthInterceptors_ServiceDescriptorCoverage(t *testing.T) {
	authn := auth.New([]string{"tok"}, 0)
	conn := startServer(t, newTestSQLiteStore(t), authn)

	for _, m := range monitorServiceDesc.Methods {
		m := m // capture
		t.Run("unary/"+m.MethodName, func(t *testing.T) {
			var reply interface{}
			err := conn.Invoke(context.Background(),
				"/"+monitorServiceDesc.ServiceName+"/"+m.MethodName,
				&GetMonitorRequest{}, &reply)
			require.Error(t, err, "method %s must reject an unauthenticated request", m.MethodName)
			assert.Equal(t, codes.Unauthenticated, status.Code(err),
				"method %s: want Unauthenticated, got %s", m.MethodName, status.Code(err))
		})
	}

	for _, s := range monitorServiceDesc.Streams {
		s := s // capture
		t.Run("stream/"+s.StreamName, func(t *testing.T) {
			stream, err := conn.NewStream(context.Background(),
				&grpc.StreamDesc{ServerStreams: s.ServerStreams},
				"/"+monitorServiceDesc.ServiceName+"/"+s.StreamName)
			require.NoError(t, err)
			_ = stream.SendMsg(&StreamAlertsRequest{})
			var msg AlertProto
			err = stream.RecvMsg(&msg)
			require.Error(t, err, "stream %s must reject an unauthenticated request", s.StreamName)
			assert.Equal(t, codes.Unauthenticated, status.Code(err),
				"stream %s: want Unauthenticated, got %s", s.StreamName, status.Code(err))
		})
	}
}

// --- unit tests for checkAuth (kept from the original file, extended) ---

func TestCheckAuth_NoAuthConfigured(t *testing.T) {
	s := &Server{auth: nil}
	err := s.checkAuth(context.Background())
	assert.NoError(t, err, "nil authenticator should allow all requests")
}

func TestCheckAuth_DisabledAuth(t *testing.T) {
	// An authenticator with no tokens is effectively disabled.
	authn := auth.New(nil, 0)
	s := &Server{auth: authn}
	err := s.checkAuth(context.Background())
	assert.NoError(t, err, "disabled authenticator should allow all requests")
}

func TestCheckAuth_ValidToken(t *testing.T) {
	authn := auth.New([]string{"test-token-123"}, 0)
	s := &Server{auth: authn}

	md := metadata.New(map[string]string{"authorization": "Bearer test-token-123"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := s.checkAuth(ctx)
	assert.NoError(t, err)
}

func TestCheckAuth_InvalidToken(t *testing.T) {
	authn := auth.New([]string{"test-token-123"}, 0)
	s := &Server{auth: authn}

	md := metadata.New(map[string]string{"authorization": "Bearer wrong-token"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := s.checkAuth(ctx)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestCheckAuth_MissingMetadata(t *testing.T) {
	authn := auth.New([]string{"test-token-123"}, 0)
	s := &Server{auth: authn}

	err := s.checkAuth(context.Background())
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestCheckAuth_MissingAuthorizationKey(t *testing.T) {
	authn := auth.New([]string{"test-token-123"}, 0)
	s := &Server{auth: authn}

	md := metadata.New(map[string]string{"other-key": "value"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	err := s.checkAuth(ctx)
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unauthenticated, st.Code())
}

func TestMonitorToProto(t *testing.T) {
	m := &store.Monitor{
		ID:          1,
		Name:        "test",
		ContractIDs: []string{"C1", "C2"},
		Enabled:     true,
		ChannelIDs:  []int64{10, 20},
	}
	p := monitorToProto(m)
	assert.Equal(t, int64(1), p.ID)
	assert.Equal(t, "test", p.Name)
	assert.Equal(t, []string{"C1", "C2"}, p.ContractIDs)
	assert.True(t, p.Enabled)
	assert.Equal(t, []int64{10, 20}, p.ChannelIDs)
}

func TestAlertToProto(t *testing.T) {
	a := &store.Alert{
		ID:        42,
		MonitorID: 1,
		RuleID:    2,
		EventID:   "evt-123",
	}
	p := alertToProto(a)
	assert.Equal(t, int64(42), p.ID)
	assert.Equal(t, int64(1), p.MonitorID)
	assert.Equal(t, "evt-123", p.EventID)
}
