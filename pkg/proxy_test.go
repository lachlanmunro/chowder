package chowder

import (
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/julienschmidt/httprouter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setupProxyTest(header int) (rw *mockResponseWriter, r *http.Request, mav *mockAntiVirus, w *string) {
	rw = &mockResponseWriter{}
	rw.On("WriteHeader", header).Once()
	rw.On("Header").Once().Return(http.Header{})
	resp := ""
	w = &resp
	rw.On("Write", mock.Anything).Once().Run(func(args mock.Arguments) {
		asByte, ok := args.Get(0).([]byte)
		if !ok {
			panic("wasn't a []byte")
		}
		*w = string(asByte)
	}).Return(0, nil)
	r = &http.Request{}
	mav = &mockAntiVirus{}
	return
}

func TestScanValidCreatesCorrectResponse(t *testing.T) {
	rw, r, mav, resp := setupProxyTest(200)
	mav.On("Scan", nil).Return(false, "ok", nil)

	sut := &Proxy{mav}

	sut.Scan(rw, r, httprouter.Params{})

	rw.AssertExpectations(t)
	mav.AssertExpectations(t)
	assert.Equal(t, `{"infected":false,"message":"ok"}`, *resp)
}

func TestScanErrCreatesCorrectResponse(t *testing.T) {
	rw, r, mav, resp := setupProxyTest(500)
	mav.On("Scan", nil).Return(false, "", errors.New("big badda boom"))

	sut := &Proxy{mav}

	sut.Scan(rw, r, httprouter.Params{})

	rw.AssertExpectations(t)
	mav.AssertExpectations(t)
	assert.Equal(t, `{"error":"big badda boom"}`, *resp)
}

func TestOkValidCreatesCorrectResponse(t *testing.T) {
	rw, r, mav, resp := setupProxyTest(200)
	mav.On("Ok").Return(true, "ok", nil)

	sut := &Proxy{mav}

	sut.Ok(rw, r, httprouter.Params{})

	rw.AssertExpectations(t)
	mav.AssertExpectations(t)
	assert.Equal(t, `{"message":"Up"}`, *resp)
}

func TestOkAntivirusDownCreatesCorrectResponse(t *testing.T) {
	rw, r, mav, resp := setupProxyTest(500)
	mav.On("Ok").Return(false, "", nil)

	sut := &Proxy{mav}

	sut.Ok(rw, r, httprouter.Params{})

	rw.AssertExpectations(t)
	mav.AssertExpectations(t)
	assert.Equal(t, `{"message":"Down"}`, *resp)
}

func TestOkErrCreatesCorrectResponse(t *testing.T) {
	rw, r, mav, resp := setupProxyTest(500)
	mav.On("Ok").Return(false, "", errors.New("big badda boom"))

	sut := &Proxy{mav}

	sut.Ok(rw, r, httprouter.Params{})

	rw.AssertExpectations(t)
	mav.AssertExpectations(t)
	assert.Equal(t, `{"message":"Down","error":"big badda boom - daemon response: "}`, *resp)
}

type mockAntiVirus struct {
	mock.Mock
}

func (m *mockAntiVirus) Scan(stream io.Reader) (ok bool, msg string, err error) {
	args := m.Called(stream)
	return args.Bool(0), args.String(1), args.Error(2)
}

func (m *mockAntiVirus) Ok() (ok bool, msg string, err error) {
	args := m.Called()
	return args.Bool(0), args.String(1), args.Error(2)
}
