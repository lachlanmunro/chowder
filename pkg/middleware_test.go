package chowder

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var (
	_ http.Handler        = &mockHandler{}
	_ http.ResponseWriter = &mockResponseWriter{}
)

func TestLoggingMiddlewareLogsPanics(t *testing.T) {
	w := &strings.Builder{}
	l := zerolog.New(w)
	m := &mockHandler{}
	m.On("ServeHTTP", mock.Anything, mock.Anything).Once().Run(func(mock.Arguments) {
		panic(errors.New("big badda boom"))
	})
	r := &http.Request{}

	assert.NotPanics(t, func() {
		LogRequests(l, m).ServeHTTP(&mockResponseWriter{}, r)
	})
	assert.Contains(t, w.String(), "big badda boom")
}

func TestLoggingMiddlewareLogs(t *testing.T) {
	w := &strings.Builder{}
	l := zerolog.New(w)
	m := &mockHandler{}
	m.On("ServeHTTP", mock.Anything, mock.Anything).Once()
	r := &http.Request{}

	sut := LogRequests(l, m)
	sut.ServeHTTP(&mockResponseWriter{}, r)
	line := w.String()

	assert.Regexp(t, `{"level":"debug","start":".{20,25}","host":"","remote-address":"","method":"","request-uri":"","proto":"","user-agent":"","status":0,"content-length":0,"duration":.+,"message":"response returned"}`, line)
}

func TestAuthMiddlewareAllowsValidAuth(t *testing.T) {
	rw := &mockResponseWriter{}
	r := &http.Request{
		Header: http.Header{
			"Authorization": []string{"password"},
		},
	}
	m := &mockHandler{}
	m.On("ServeHTTP", rw, r).Once()
	u := map[string]string{
		"password": "user",
	}

	sut := HeaderAuth(u, m)
	sut.ServeHTTP(rw, r)

	rw.AssertExpectations(t)
	m.AssertExpectations(t)
}

func TestAuthMiddlewareBlocksInvalidAuth(t *testing.T) {
	rw := &mockResponseWriter{}
	rw.Mock.On("WriteHeader", 401).Once()
	h := http.Header{}
	rw.Mock.On("Header").Once().Return(h)
	resp := ""
	rw.Mock.On("Write", mock.Anything).Once().Run(func(args mock.Arguments) {
		asByte, ok := args.Get(0).([]byte)
		if !ok {
			panic("wasn't a []byte")
		}
		resp = string(asByte)
	}).Return(0, nil)
	r := &http.Request{
		Header: http.Header{
			"Authorization": []string{"notpassword"},
		}}
	m := &mockHandler{}
	u := map[string]string{
		"password": "user",
	}

	sut := HeaderAuth(u, m)
	sut.ServeHTTP(rw, r)

	rw.AssertExpectations(t)
	m.AssertExpectations(t)
	assert.Equal(t, `{"message":"token 'notpassword' not recognised","error":"Unauthorized"}`, resp)
}

func TestAuthMiddlewareBlocksNoAuthSupplied(t *testing.T) {
	rw := &mockResponseWriter{}
	rw.Mock.On("WriteHeader", 401).Once()
	h := http.Header{}
	rw.Mock.On("Header").Once().Return(h)
	resp := ""
	rw.Mock.On("Write", mock.Anything).Once().Run(func(args mock.Arguments) {
		asByte, ok := args.Get(0).([]byte)
		if !ok {
			panic("wasn't a []byte")
		}
		resp = string(asByte)
	}).Return(0, nil)
	r := &http.Request{}
	m := &mockHandler{}
	u := map[string]string{
		"password": "user",
	}

	sut := HeaderAuth(u, m)
	sut.ServeHTTP(rw, r)

	rw.AssertExpectations(t)
	m.AssertExpectations(t)
	assert.Equal(t, `{"message":"no authorisation token supplied","error":"Unauthorized"}`, resp)
}

type mockHandler struct {
	mock.Mock
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
}

type mockResponseWriter struct {
	mock.Mock
}

func (m *mockResponseWriter) Header() http.Header {
	args := m.Called()
	var h http.Header
	var ok bool
	if h, ok = args.Get(0).(http.Header); !ok {
		panic(fmt.Errorf("assert: arguments: Failed because object wasn't correct type: %v", args.Get(0)))
	}
	return h
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.Called(statusCode)
}
