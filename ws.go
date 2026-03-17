package wsgo

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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
	stateConnecting int32 = iota
	stateOpen
	stateClosing
	stateClosed
)

var (
	ErrConnectionClosed = errors.New("connection closed")
	ErrHandshakeFailed  = errors.New("handshake failed")
	ErrInvalidFrame     = errors.New("invalid frame")
	ErrTimeout          = errors.New("operation timeout")
	ErrMessageTooLarge  = errors.New("message too large")
)

type WebSocket struct {
	conn           net.Conn
	handlers       map[int]func([]byte)
	handlersMutex  sync.RWMutex
	state          int32
	sendMutex      sync.Mutex
	closeOnce      sync.Once
	readTimeout    time.Duration
	writeTimeout   time.Duration
	pingInterval   time.Duration
	lastPongTime   time.Time
	pongMutex      sync.RWMutex
	closeNotifier  chan struct{}
	logger         Logger
	maxMessageSize int64
	isServer       bool
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

func NewWebSocket(conn net.Conn, config *WebSocketConfig, isServer bool) *WebSocket {
	if config == nil {
		config = DefaultConfig()
	}

	return &WebSocket{
		conn:           conn,
		handlers:       make(map[int]func([]byte)),
		state:          stateConnecting,
		readTimeout:    config.ReadTimeout,
		writeTimeout:   config.WriteTimeout,
		pingInterval:   config.PingInterval,
		lastPongTime:   time.Now(),
		closeNotifier:  make(chan struct{}),
		logger:         config.Logger,
		maxMessageSize: config.MaxMessageSize,
		isServer:       isServer,
	}
}

func (ws *WebSocket) On(opcode int, handler func([]byte)) {
	ws.handlersMutex.Lock()
	defer ws.handlersMutex.Unlock()
	ws.handlers[opcode] = handler
}

func (ws *WebSocket) getState() int32 {
	return atomic.LoadInt32(&ws.state)
}

func (ws *WebSocket) setState(state int32) {
	atomic.StoreInt32(&ws.state, state)
}

func (ws *WebSocket) isOpen() bool {
	return ws.getState() == stateOpen
}

func (ws *WebSocket) Send(opcode int, data []byte) error {
	if !ws.isOpen() {
		return ErrConnectionClosed
	}

	if int64(len(data)) > ws.maxMessageSize {
		return fmt.Errorf("%w: %d > %d", ErrMessageTooLarge, len(data), ws.maxMessageSize)
	}

	ws.sendMutex.Lock()
	defer ws.sendMutex.Unlock()

	if ws.writeTimeout > 0 {
		if err := ws.conn.SetWriteDeadline(time.Now().Add(ws.writeTimeout)); err != nil {
			return err
		}
	}

	frame, err := ws.createFrame(opcode, data)
	if err != nil {
		return err
	}

	_, err = ws.conn.Write(frame)
	if err != nil {
		ws.logger.Error("Write error: %v", err)
		ws.Close()
		return err
	}

	return nil
}

func (ws *WebSocket) createFrame(opcode int, data []byte) ([]byte, error) {
	headerByte := byte(0x80 | opcode)
	
	needsMask := !ws.isServer
	
	payloadLen := len(data)
	
	headerSize := 2
	if payloadLen >= 126 {
		if payloadLen < 65536 {
			headerSize += 2
		} else {
			headerSize += 8
		}
	}
	if needsMask {
		headerSize += 4
	}
	
	frame := make([]byte, headerSize+payloadLen)
	
	frame[0] = headerByte
	
	secondByte := byte(0)
	if needsMask {
		secondByte |= 0x80
	}
	
	if payloadLen < 126 {
		secondByte |= byte(payloadLen)
		frame[1] = secondByte
	} else if payloadLen < 65536 {
		secondByte |= 126
		frame[1] = secondByte
		frame[2] = byte(payloadLen >> 8)
		frame[3] = byte(payloadLen)
	} else {
		secondByte |= 127
		frame[1] = secondByte
		for i := 0; i < 8; i++ {
			frame[2+i] = byte(payloadLen >> uint((7-i)*8))
		}
	}
	
	dataOffset := headerSize
	maskOffset := 2
	
	if payloadLen >= 126 {
		if payloadLen < 65536 {
			maskOffset = 4
		} else {
			maskOffset = 10
		}
	}
	
	if needsMask {
		maskKey := make([]byte, 4)
		if _, err := rand.Read(maskKey); err != nil {
			return nil, fmt.Errorf("failed to generate mask key: %w", err)
		}
		
		copy(frame[maskOffset:maskOffset+4], maskKey)
		
		copy(frame[dataOffset:], data)
		for i := 0; i < payloadLen; i++ {
			frame[dataOffset+i] ^= maskKey[i%4]
		}
	} else {
		copy(frame[dataOffset:], data)
	}
	
	return frame, nil
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

		_ = ws.Send(opClose, []byte{})

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
		if err := ws.conn.SetReadDeadline(time.Now().Add(ws.readTimeout)); err != nil {
			return err
		}
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

	if ws.isServer && !masked {
		return fmt.Errorf("%w: client frames must be masked", ErrInvalidFrame)
	}
	if !ws.isServer && masked {
		return fmt.Errorf("%w: server frames must not be masked", ErrInvalidFrame)
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
		_ = ws.Send(opClose, []byte("Message too large"))
		return ErrMessageTooLarge
	}

	var maskKey []byte
	if masked {
		maskKey = make([]byte, 4)
		if _, err := io.ReadFull(ws.conn, maskKey); err != nil {
			return err
		}
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(ws.conn, payload); err != nil {
		return err
	}

	if masked {
		for i := 0; i < payloadLen; i++ {
			payload[i] ^= maskKey[i%4]
		}
	}

	switch opcode {
	case opPing:
		ws.logger.Debug("Received ping")
		_ = ws.Send(opPong, payload)
	case opPong:
		ws.logger.Debug("Received pong")
		ws.updatePongTime()
	case opClose:
		ws.logger.Info("Received close frame")
		ws.Close()
	default:
		if fin {
			ws.handlersMutex.RLock()
			handler, ok := ws.handlers[opcode]
			ws.handlersMutex.RUnlock()
			
			if ok {
				go handler(payload)
			}
		}
	}

	return nil
}

func (ws *WebSocket) pingLoop() {
	if ws.pingInterval <= 0 {
		return
	}

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

	if ws.isServer {
		go ws.pingLoop()
	}

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
	port           string
	onConnect      func(*WebSocket)
	onDisconnect   func(*WebSocket)
	config         *WebSocketConfig
	clients        sync.Map
	listener       net.Listener
	shutdownChan   chan struct{}
	logger         Logger
	maxConnections int32
	connections    int32
}

func NewWebSocketServer(port string, config *WebSocketConfig) *WebSocketServer {
	if config == nil {
		config = DefaultConfig()
	}

	return &WebSocketServer{
		port:           port,
		config:         config,
		shutdownChan:   make(chan struct{}),
		logger:         config.Logger,
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
	atomic.StoreInt32(&s.maxConnections, int32(max))
}

func (s *WebSocketServer) GetClientsCount() int32 {
	return atomic.LoadInt32(&s.connections)
}

func (s *WebSocketServer) GetClients() []*WebSocket {
	var clients []*WebSocket
	s.clients.Range(func(key, value interface{}) bool {
		if ws, ok := key.(*WebSocket); ok {
			clients = append(clients, ws)
		}
		return true
	})
	return clients
}

func (s *WebSocketServer) Broadcast(opcode int, data []byte) {
	s.clients.Range(func(key, value interface{}) bool {
		if ws, ok := key.(*WebSocket); ok {
			go ws.Send(opcode, data)
		}
		return true
	})
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

	if atomic.LoadInt32(&s.connections) >= atomic.LoadInt32(&s.maxConnections) {
		s.logger.Error("Max connections reached, rejecting")
		conn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	reader := bufio.NewReader(conn)
	
	request := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			s.logger.Error("Failed to read handshake: %v", err)
			return
		}
		request += line
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	conn.SetReadDeadline(time.Time{})

	err := s.performHandshake(conn, request)
	if err != nil {
		s.logger.Error("Handshake failed: %v", err)
		return
	}

	ws := NewWebSocket(conn, s.config, true)

	s.clients.Store(ws, true)
	atomic.AddInt32(&s.connections, 1)

	s.logger.Info("New client connected. Total: %d", s.GetClientsCount())

	if s.onConnect != nil {
		s.onConnect(ws)
	}

	ws.Listen()

	s.clients.Delete(ws)
	atomic.AddInt32(&s.connections, -1)

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

	go func() {
		<-s.shutdownChan
		s.logger.Info("Shutdown signal received, closing listener")
		s.listener.Close()
	}()

	for {
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

func (s *WebSocketServer) Stop() {
	close(s.shutdownChan)

	s.clients.Range(func(key, value interface{}) bool {
		if ws, ok := key.(*WebSocket); ok {
			ws.Close()
		}
		return true
	})
}

var (
	defaultServer *WebSocketServer
	serverMutex   sync.Mutex
)

func StartServer(port string, onMessage func(conn *WebSocket, data []byte)) error {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	if defaultServer != nil {
		return errors.New("server already running")
	}

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

func GetStats() map[string]interface{} {
	serverMutex.Lock()
	defer serverMutex.Unlock()

	stats := make(map[string]interface{})
	if defaultServer != nil {
		stats["clients"] = defaultServer.GetClientsCount()
		stats["max_connections"] = defaultServer.maxConnections
	}

	return stats
}
