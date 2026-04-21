// Command tailscale-chat is a minimal web chat that runs as a node on your
// Tailscale tailnet. It uses tsnet to join the tailnet so the chat is only
// reachable by other tailnet members, and it uses the Tailscale LocalClient's
// WhoIs RPC to identify each connected user automatically — no separate
// login is required.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"tailscale.com/client/tailscale"
	"tailscale.com/tsnet"
)

//go:embed static/*
var staticFS embed.FS

// Message is a single chat message broadcast to every connected client.
type Message struct {
	ID        int64     `json:"id"`
	User      string    `json:"user"`
	Login     string    `json:"login"`
	Text      string    `json:"text"`
	Timestamp time.Time `json:"ts"`
}

// store keeps a bounded in-memory ring of the most recent messages and
// appends every new message to an on-disk JSON Lines log so history survives
// process restarts.
type store struct {
	mu       sync.Mutex
	path     string
	messages []Message
	nextID   int64
	maxKeep  int
}

func newStore(path string, maxKeep int) (*store, error) {
	s := &store{path: path, maxKeep: maxKeep}
	if path == "" {
		return s, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	for dec.More() {
		var m Message
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		s.messages = append(s.messages, m)
		if m.ID >= s.nextID {
			s.nextID = m.ID + 1
		}
	}
	if len(s.messages) > s.maxKeep {
		s.messages = s.messages[len(s.messages)-s.maxKeep:]
	}
	return s, nil
}

func (s *store) append(m *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m.ID = s.nextID
	s.nextID++
	s.messages = append(s.messages, *m)
	if len(s.messages) > s.maxKeep {
		s.messages = s.messages[len(s.messages)-s.maxKeep:]
	}
	if s.path == "" {
		return nil
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	return enc.Encode(m)
}

func (s *store) recent() []Message {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Message, len(s.messages))
	copy(out, s.messages)
	return out
}

// hub fans out messages to all currently-connected WebSocket clients.
type hub struct {
	mu      sync.Mutex
	clients map[*client]struct{}
}

func newHub() *hub { return &hub{clients: map[*client]struct{}{}} }

func (h *hub) add(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.clients[c] = struct{}{}
}

func (h *hub) remove(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.clients, c)
}

func (h *hub) broadcast(m Message) {
	h.mu.Lock()
	clients := make([]*client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.Unlock()
	for _, c := range clients {
		select {
		case c.send <- m:
		default:
			// Slow client — drop it to avoid blocking the hub.
			go c.closeSlow()
		}
	}
}

type client struct {
	conn      *websocket.Conn
	send      chan Message
	user      string
	login     string
	closeOnce sync.Once
}

func (c *client) closeSlow() {
	c.closeOnce.Do(func() {
		_ = c.conn.Close(websocket.StatusPolicyViolation, "client too slow")
	})
}

// server wires the tsnet node, the LocalClient (used for WhoIs identity
// lookups) and the HTTP handlers together.
type server struct {
	lc    *tailscale.LocalClient
	hub   *hub
	store *store
}

// identify resolves the remote address of an incoming request to a tailnet
// identity via the Tailscale LocalClient's WhoIs RPC.
func (s *server) identify(r *http.Request) (displayName, loginName string, err error) {
	who, err := s.lc.WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		return "", "", err
	}
	display := who.UserProfile.DisplayName
	login := who.UserProfile.LoginName
	if display == "" {
		display = login
	}
	return display, login, nil
}

func (s *server) handleWhoAmI(w http.ResponseWriter, r *http.Request) {
	name, login, err := s.identify(r)
	if err != nil {
		http.Error(w, "could not identify caller: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]string{"user": name, "login": login})
}

func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.store.recent())
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	name, login, err := s.identify(r)
	if err != nil {
		http.Error(w, "could not identify caller: "+err.Error(), http.StatusInternalServerError)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Same-origin; tsnet already restricts reachability.
	})
	if err != nil {
		log.Printf("ws accept: %v", err)
		return
	}
	c := &client{conn: conn, send: make(chan Message, 32), user: name, login: login}
	s.hub.add(c)
	defer s.hub.remove(c)
	defer conn.Close(websocket.StatusNormalClosure, "bye")

	// Send history on connect.
	for _, m := range s.store.recent() {
		if err := wsjson.Write(r.Context(), conn, m); err != nil {
			return
		}
	}

	// Writer goroutine: drain c.send to the socket.
	writerCtx, cancelWriter := context.WithCancel(r.Context())
	defer cancelWriter()
	go func() {
		for {
			select {
			case <-writerCtx.Done():
				return
			case m := <-c.send:
				ctx, cancel := context.WithTimeout(writerCtx, 5*time.Second)
				err := wsjson.Write(ctx, conn, m)
				cancel()
				if err != nil {
					return
				}
			}
		}
	}()

	// Reader loop: accept inbound messages from this client.
	for {
		var in struct {
			Text string `json:"text"`
		}
		if err := wsjson.Read(r.Context(), conn, &in); err != nil {
			return
		}
		if len(in.Text) == 0 {
			continue
		}
		if len(in.Text) > 4000 {
			in.Text = in.Text[:4000]
		}
		msg := Message{User: c.user, Login: c.login, Text: in.Text, Timestamp: time.Now().UTC()}
		if err := s.store.append(&msg); err != nil {
			log.Printf("store append: %v", err)
			continue
		}
		s.hub.broadcast(msg)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func run() error {
	hostname := flag.String("hostname", "chat", "Tailscale hostname to advertise for this chat node")
	stateDir := flag.String("state-dir", "./tsnet-state", "Directory for tsnet state (node key, certs)")
	dbPath := flag.String("db", "./chat.jsonl", "Path to the append-only message log")
	addr := flag.String("addr", ":80", "Address to listen on inside the tailnet")
	historyKeep := flag.Int("history", 200, "Number of recent messages kept in memory/served on connect")
	flag.Parse()

	if err := os.MkdirAll(*stateDir, 0o700); err != nil {
		return err
	}
	if dir := filepath.Dir(*dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}

	st, err := newStore(*dbPath, *historyKeep)
	if err != nil {
		return err
	}

	srv := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *stateDir,
		Logf:     func(format string, args ...any) { log.Printf("tsnet: "+format, args...) },
	}
	defer srv.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if _, err := srv.Up(ctx); err != nil {
		return err
	}
	lc, err := srv.LocalClient()
	if err != nil {
		return err
	}

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return err
	}

	s := &server{lc: lc, hub: newHub(), store: st}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticSub)))
	mux.HandleFunc("/api/whoami", s.handleWhoAmI)
	mux.HandleFunc("/api/messages", s.handleMessages)
	mux.HandleFunc("/ws", s.handleWS)

	ln, err := srv.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	status, err := lc.Status(ctx)
	if err == nil && status.Self != nil {
		log.Printf("tailscale-chat up on http://%s (tailnet: %s)", *hostname, status.CurrentTailnet.Name)
		for _, ip := range status.Self.TailscaleIPs {
			log.Printf("  also reachable at http://%s%s", ip, *addr)
		}
	}

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
		defer c()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()
	if err := httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("tailscale-chat: %v", err)
	}
}
