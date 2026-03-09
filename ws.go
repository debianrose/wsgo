package ws

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)


const (
	opContinuation = 0x0
	opText         = 0x1
	opBinary       = 0x2
	opClose        = 0x8
	opPing         = 0x9
	opPong         = 0xA
)


const (
	stateConnecting = iota
	stateOpen
	stateClosing
	stateClosed
)


var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrHandshakeFailed  = errors.New("handshake failed")
	ErrInvalidFrame     = errors.New("invalid frame")
	ErrTimeout          = errors.New("operation timeout")
)


type WebSocket struct {
	conn           net.Conn
	handlers       map[int]func([]byte)
	state          int
	stateMutex     sync.RWMutex
	sendMutex      sync.Mutex
	closeOnce      sync.Once
	readTimeout    time.Duration
	writeTimeout   time.Duration
	pingInterval   time.Duration
	lastPongTime   time.Time
	pongMutex      sync.RWMutex
	messageQueue   chan []byte
	closeNotifier  chan struct{}
	logger         Logger
	maxMessageSize int64
}


type Logger interface {
	Info(format string, v ...interface{})
	Error(format string, v ...interface{})
	Debug(format string, v ...interface{})
}


type DefaultLogger struct{}

func (l *DefaultLogger) Info(format string, v ...interface{}) {
	fmt.Printf("[INFO] "+format+"\n", v...)
}

func (l *DefaultLogger) Error(format string, v ...interface{}) {
	fmt.Printf("[ERROR] "+format+"\n", v...)
}

func (l *DefaultLogger) Debug(format string, v ...interface{}) {
	fmt.Printf("[DEBUG] "+format+"\n", v...)
}


type WebSocketConfig struct {
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	PingInterval   time.Duration
	MaxMessageSize int64
	Logger         Logger
}


func DefaultConfig() *WebSocketConfig {
	return &WebSocketConfig{
		ReadTimeout:    60 * time.Second,
		WriteTimeout:   10 * time.Second,
		PingInterval:   30 * time.Second,
		MaxMessageSize: 1024 * 1024,
		Logger:         &DefaultLogger{},
	}
}


func NewWebSocket(conn net.Conn, config *WebSocketConfig) *WebSocket {
	if config == nil {
		config = DefaultConfig()
	}

	ws := &WebSocket{
		conn:           conn,
		handlers:       make(map[int]func([]byte)),
		state:          stateConnecting,
		readTimeout:    config.ReadTimeout,
		writeTimeout:   config.WriteTimeout,
		pingInterval:   config.PingInterval,
		lastPongTime:   time.Now(),
		messageQueue:   make(chan []byte, 100),
		closeNotifier:  make(chan struct{}),
		logger:         config.Logger,
		maxMessageSize: config.MaxMessageSize,
	}

	return ws
}


func (ws *WebSocket) On(opcode int, handler func([]byte)) {
	ws.handlers[opcode] = handler
}


func (ws *WebSocket) getState() int {
	ws.stateMutex.RLock()
	defer ws.stateMutex.RUnlock()
	return ws.state
}


func (ws *WebSocket) setState(state int) {
	ws.stateMutex.Lock()
	defer ws.stateMutex.Unlock()
	ws.state = state
}


func (ws *WebSocket) isOpen() bool {
	return ws.getState() == stateOpen
}


func (ws *WebSocket) Send(opcode int, data []byte) error {
	if !ws.isOpen() {
		return ErrConnectionClosed
	}

	if int64(len(data)) > ws.maxMessageSize {
		return fmt.Errorf("message too large: %d > %d", len(data), ws.maxMessageSize)
	}

	ws.sendMutex.Lock()
	defer ws.sendMutex.Unlock()


	if ws.writeTimeout > 0 {
		ws.conn.SetWriteDeadline(time.Now().Add(ws.writeTimeout))
	}


	frame := make([]byte, 2)
	frame[0] = byte(0x80 | opcode)


	if len(data) < 126 {
		frame[1] = byte(len(data))
		frame = append(frame, data...)
	} else if len(data) < 65536 {
		frame[1] = 126
		frame = append(frame, byte(len(data)>>8), byte(len(data)))
		frame = append(frame, data...)
	} else {
		frame[1] = 127
		for i := 7; i >= 0; i-- {
			frame = append(frame, byte(len(data)>>uint(i*8)))
		}
		frame = append(frame, data...)
	}

	_, err := ws.conn.Write(frame)
	if err != nil {
		ws.logger.Error("Write error: %v", err)
		ws.Close()
		return err
	}

	return nil
}


func (ws *WebSocket) SendText(message string) error {
	return ws.Send(opText, []byte(message))
}


func (ws *WebSocket) SendBinary(data []byte) error {
	return ws.Send(opBinary, data)
}


func (ws *WebSocket) Close() error {
	var err error
	ws.closeOnce.Do(func() {
		ws.setState(stateClosing)


		ws.Send(opClose, []byte{})


		close(ws.closeNotifier)


		err = ws.conn.Close()
		ws.setState(stateClosed)
		ws.logger.Info("Connection closed")
	})
	return err
}


func (ws *WebSocket) updatePongTime() {
	ws.pongMutex.Lock()
	defer ws.pongMutex.Unlock()
	ws.lastPongTime = time.Now()
}


func (ws *WebSocket) getLastPongTime() time.Time {
	ws.pongMutex.RLock()
	defer ws.pongMutex.RUnlock()
	return ws.lastPongTime
}


func (ws *WebSocket) handleFrame() error {

	if ws.readTimeout > 0 {
		ws.conn.SetReadDeadline(time.Now().Add(ws.readTimeout))
	}

	header := make([]byte, 2)
	_, err := io.ReadFull(ws.conn, header)
	if err != nil {
		return err
	}

	fin := (header[0] & 0x80) != 0
	opcode := int(header[0] & 0x0F)
	masked := (header[1] & 0x80) != 0
	payloadLen := int(header[1] & 0x7F)


	if !masked {
		return ErrInvalidFrame
	}


	if payloadLen == 126 {
		extLen := make([]byte, 2)
		if _, err := io.ReadFull(ws.conn, extLen); err != nil {
			return err
		}
		payloadLen = int(extLen[0])<<8 | int(extLen[1])
	} else if payloadLen == 127 {
		extLen := make([]byte, 8)
		if _, err := io.ReadFull(ws.conn, extLen); err != nil {
			return err
		}
		payloadLen = 0
		for i := 0; i < 8; i++ {
			payloadLen |= int(extLen[i]) << uint((7-i)*8)
		}
	}


	if int64(payloadLen) > ws.maxMessageSize {
		ws.logger.Error("Message too large: %d bytes", payloadLen)
		ws.Send(opClose, []byte("Message too large"))
		return ErrInvalidFrame
	}


	maskKey := make([]byte, 4)
	if _, err := io.ReadFull(ws.conn, maskKey); err != nil {
		return err
	}


	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.conn, payload); err != nil {
		return err
	}


	for i := 0; i < payloadLen; i++ {
		payload[i] ^= maskKey[i%4]
	}


	switch opcode {
	case opPing:
		ws.logger.Debug("Received ping")
		ws.Send(opPong, payload)
	case opPong:
		ws.logger.Debug("Received pong")
		ws.updatePongTime()
	case opClose:
		ws.logger.Info("Received close frame")
		ws.Close()
	default:
		if handler, ok := ws.handlers[opcode]; ok && fin {

			go handler(payload)
		}
	}

	return nil
}


func (ws *WebSocket) pingLoop() {
	ticker := time.NewTicker(ws.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if !ws.isOpen() {
				return
			}


			if time.Since(ws.getLastPongTime()) > ws.pingInterval*3 {
				ws.logger.Error("Pong timeout, closing connection")
				ws.Close()
				return
			}


			if err := ws.Send(opPing, []byte{}); err != nil {
				ws.logger.Error("Failed to send ping: %v", err)
				return
			}
			ws.logger.Debug("Sent ping")

		case <-ws.closeNotifier:
			return
		}
	}
}


func (ws *WebSocket) Listen() {
	ws.setState(stateOpen)
	ws.logger.Info("Connection established")


	go ws.pingLoop()

	for ws.isOpen() {
		err := ws.handleFrame()
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "use of closed network connection") {
				ws.logger.Error("Error handling frame: %v", err)
			}
			break
		}
	}

	ws.Close()
}


type WebSocketServer struct {
	port          string
	onConnect     func(*WebSocket)
	onDisconnect  func(*WebSocket)
	config        *WebSocketConfig
	clients       map[*WebSocket]bool
	clientsMutex  sync.RWMutex
	listener      net.Listener
	shutdownChan  chan struct{}
	logger        Logger
	maxConnections int
	connections   int32
}


func NewWebSocketServer(port string, config *WebSocketConfig) *WebSocketServer {
	if config == nil {
		config = DefaultConfig()
	}

	return &WebSocketServer{
		port:          port,
		config:        config,
		clients:       make(map[*WebSocket]bool),
		shutdownChan:  make(chan struct{}),
		logger:        config.Logger,
		maxConnections: 1000,
	}
}


func (s *WebSocketServer) OnConnect(handler func(*WebSocket)) {
	s.onConnect = handler
}


func (s *WebSocketServer) OnDisconnect(handler func(*WebSocket)) {
	s.onDisconnect = handler
}


func (s *WebSocketServer) SetMaxConnections(max int) {
	s.maxConnections = max
}


func (s *WebSocketServer) GetClientsCount() int {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()
	return len(s.clients)
}


func (s *WebSocketServer) GetClients() []*WebSocket {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	clients := make([]*WebSocket, 0, len(s.clients))
	for client := range s.clients {
		clients = append(clients, client)
	}
	return clients
}


func (s *WebSocketServer) Broadcast(opcode int, data []byte) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	for client := range s.clients {
		go client.Send(opcode, data)
	}
}


func (s *WebSocketServer) BroadcastText(message string) {
	s.Broadcast(opText, []byte(message))
}


func (s *WebSocketServer) performHandshake(conn net.Conn, request string) error {

	lines := strings.Split(request, "\r\n")
	var key string
	for _, line := range lines {
		if strings.HasPrefix(line, "Sec-WebSocket-Key: ") {
			key = strings.TrimPrefix(line, "Sec-WebSocket-Key: ")
			break
		}
	}

	if key == "" {
		return ErrHandshakeFailed
	}


	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	acceptKey := base64.StdEncoding.EncodeToString(hash[:])


	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	_, err := conn.Write([]byte(response))
	return err
}


func (s *WebSocketServer) handleConnection(conn net.Conn) {
	defer conn.Close()


	if s.GetClientsCount() >= s.maxConnections {
		s.logger.Error("Max connections reached (%d), rejecting", s.maxConnections)
		conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}


	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buffer := make([]byte, 2048)
	n, err := conn.Read(buffer)
	if err != nil {
		s.logger.Error("Failed to read handshake: %v", err)
		return
	}


	conn.SetReadDeadline(time.Time{})


	err = s.performHandshake(conn, string(buffer[:n]))
	if err != nil {
		s.logger.Error("Handshake failed: %v", err)
		return
	}


	ws := NewWebSocket(conn, s.config)


	s.clientsMutex.Lock()
	s.clients[ws] = true
	s.clientsMutex.Unlock()

	s.logger.Info("New client connected. Total: %d", s.GetClientsCount())


	if s.onConnect != nil {
		s.onConnect(ws)
	}


	ws.Listen()


	s.clientsMutex.Lock()
	delete(s.clients, ws)
	s.clientsMutex.Unlock()


	if s.onDisconnect != nil {
		s.onDisconnect(ws)
	}

	s.logger.Info("Client disconnected. Total: %d", s.GetClientsCount())
}


func (s *WebSocketServer) Start() error {
	listener, err := net.Listen("tcp", ":"+s.port)
	if err != nil {
		return err
	}

	s.listener = listener
	s.logger.Info("WebSocket server started on port %s", s.port)

	for {
		select {
		case <-s.shutdownChan:
			s.logger.Info("Server shutting down...")
			return nil
		default:
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-s.shutdownChan:
					return nil
				default:
					s.logger.Error("Accept error: %v", err)
					continue
				}
			}

			go s.handleConnection(conn)
		}
	}
}


func (s *WebSocketServer) Stop() {
	close(s.shutdownChan)

	if s.listener != nil {
		s.listener.Close()
	}


	s.clientsMutex.RLock()
	for client := range s.clients {
		client.Close()
	}
	s.clientsMutex.RUnlock()
}


var defaultServer *WebSocketServer
var serverMutex sync.Mutex


func StartServer(port string, onMessage func(conn *WebSocket, data []byte)) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	config := DefaultConfig()
	defaultServer = NewWebSocketServer(port, config)

	defaultServer.OnConnect(func(ws *WebSocket) {
		config.Logger.Info("New client connected")


		ws.On(opText, func(data []byte) {

			defer func() {
				if r := recover(); r != nil {
					config.Logger.Error("Recovered from panic: %v", r)
				}
			}()
			onMessage(ws, data)
		})


		ws.SendText("Welcome to WebSocket server!")
	})

	defaultServer.OnDisconnect(func(ws *WebSocket) {
		config.Logger.Info("Client disconnected")
	})

	return defaultServer.Start()
}


func StopServer() error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	if defaultServer != nil {
		defaultServer.Stop()
		defaultServer = nil
	}
	return nil
}


func SendMessage(ws *WebSocket, message string) error {
	return ws.SendText(message)
}


func SendMessageWithTimeout(ws *WebSocket, message string, timeout time.Duration) error {
	if !ws.isOpen() {
		return ErrConnectionClosed
	}

	done := make(chan error, 1)
	go func() {
		done <- ws.SendText(message)
	}()

	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return ErrTimeout
	}
}


var globalClients = make(map[*WebSocket]bool)
var globalClientsMutex sync.RWMutex


func RegisterClient(ws *WebSocket) {
	globalClientsMutex.Lock()
	defer globalClientsMutex.Unlock()
	globalClients[ws] = true
}


func UnregisterClient(ws *WebSocket) {
	globalClientsMutex.Lock()
	defer globalClientsMutex.Unlock()
	delete(globalClients, ws)
}


func BroadcastMessage(message string) {
	globalClientsMutex.RLock()
	defer globalClientsMutex.RUnlock()

	for ws := range globalClients {
		go ws.SendText(message)
	}
}


func GetStats() map[string]interface{} {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	stats := make(map[string]interface{})
	if defaultServer != nil {
		stats["clients"] = defaultServer.GetClientsCount()
		stats["max_connections"] = defaultServer.maxConnections
	}
	stats["global_clients"] = len(globalClients)

	return stats
}
