package chowder

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

const (
	testConnstring = "test connection string"
	testText       = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum"
)

var _ net.Conn = &mockConn{}

func TestScanCorrectlyMakesClamAVScan(t *testing.T) {
	sut, mockConn := setupClamAVTest(t)
	command := []byte("zINSTREAM\000")
	mockConn.On("Write", command).Return(len(command), nil).Once()
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(testText)))
	mockConn.On("Write", prefix).Return(len(prefix), nil).Once()
	body := []byte(testText)
	mockConn.On("Write", body).Return(len(testText), nil).Once()
	emptyChunk := []byte{0, 0, 0, 0}
	mockConn.On("Write", emptyChunk).Return(len(emptyChunk), nil).Once()
	resp := []byte("nothing\000")
	mockConn.On("Read", mock.AnythingOfType("[]uint8")).Run(func(args mock.Arguments) {
		writeTo := args.Get(0).([]byte)
		copy(writeTo, resp)
	}).Return(len(resp), io.EOF).Once()
	mockConn.On("Close").Return(nil).Once()
	in := strings.NewReader(testText)
	writtenValue := &dto.Metric{}
	written.Write(writtenValue)
	initialWritten := *writtenValue.Counter.Value
	readValue := &dto.Metric{}
	read.Write(readValue)
	initialRead := *readValue.Counter.Value

	infected, message, err := sut.Scan(in)

	written.Write(writtenValue)
	read.Write(readValue)
	assert.False(t, infected)
	assert.Equal(t, "nothing", message)
	assert.Nil(t, err)
	assert.Equal(t, float64(len(command)+len(prefix)+len(body)+len(emptyChunk)), *writtenValue.Counter.Value-initialWritten)
	assert.Equal(t, float64(len(resp)), *readValue.Counter.Value-initialRead)
	mockConn.AssertExpectations(t)
}

func TestOKCorrectlyMakesClamAVPing(t *testing.T) {
	sut, mockConn := setupClamAVTest(t)
	command := []byte("zPING\000")
	mockConn.On("Write", command).Return(len(command), nil).Once()
	resp := []byte("PONG\000")
	mockConn.On("Read", mock.AnythingOfType("[]uint8")).Run(func(args mock.Arguments) {
		writeTo := args.Get(0).([]byte)
		copy(writeTo, resp)
	}).Return(len(resp), io.EOF).Once()
	mockConn.On("Close").Return(nil).Once()

	ok, message, err := sut.Ok()
	assert.True(t, ok)
	assert.Equal(t, "PONG", message)
	assert.Nil(t, err)
	mockConn.AssertExpectations(t)
}

func setupClamAVTest(t *testing.T) (VirusScanner, *mockConn) {
	m := &mockConn{}
	sut := NewClamAV(testConnstring)
	asClamAV := sut.(*ClamAV)
	asClamAV.dial = func() (net.Conn, error) {
		return m, nil
	}

	return asClamAV, m
}

type mockConn struct {
	mock.Mock
}

// Read mocks a net.Conn interface function
func (m *mockConn) Read(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

// Write mocks a net.Conn interface function
func (m *mockConn) Write(b []byte) (n int, err error) {
	args := m.Called(b)
	return args.Int(0), args.Error(1)
}

// Close mocks a net.Conn interface function
func (m *mockConn) Close() error {
	return m.Called().Error(0)
}

// LocalAddr mocks a net.Conn interface function
func (m *mockConn) LocalAddr() net.Addr {
	args := m.Called()
	var addr net.Addr
	if arg := args.Get(0); arg != nil {
		addr = arg.(net.Addr)
	}

	return addr
}

// RemoteAddr mocks a net.Conn interface function
func (m *mockConn) RemoteAddr() net.Addr {
	args := m.Called()
	var addr net.Addr
	if arg := args.Get(0); arg != nil {
		addr = arg.(net.Addr)
	}

	return addr
}

// SetDeadline mocks a net.Conn interface function
func (m *mockConn) SetDeadline(t time.Time) error {
	return m.Called(t).Error(0)
}

// SetReadDeadline mocks a net.Conn interface function
func (m *mockConn) SetReadDeadline(t time.Time) error {
	return m.Called(t).Error(0)
}

// SetWriteDeadline mocks a net.Conn interface function
func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return m.Called(t).Error(0)
}
