// Copyright 2025 Leon Hwang.
// SPDX-License-Identifier: Apache-2.0

package bpfsnoop

type Session struct {
	started uint32
	outputs []string
}

type Sessions struct {
	sessions map[uint64]*Session
}

func NewSessions() *Sessions {
	return &Sessions{
		sessions: make(map[uint64]*Session),
	}
}

func (s *Sessions) Add(sessID uint64, started uint32) *Session {
	sess := &Session{started: started}
	s.sessions[sessID] = sess
	return sess
}

func (s *Sessions) Get(sessID uint64) (*Session, bool) {
	sess, ok := s.sessions[sessID]
	return sess, ok
}

func (s *Sessions) GetAndDel(sessID uint64) (*Session, bool) {
	sess, ok := s.sessions[sessID]
	if ok {
		delete(s.sessions, sessID)
	}
	return sess, ok
}
