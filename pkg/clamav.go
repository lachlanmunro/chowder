package chowder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
)

var (
	errDeferNoResponse = errors.New("Response triggered defer without setting")
	instream           = newCommand("INSTREAM")
	ping               = newCommand("PING")
	emptyChunk         = []byte{0, 0, 0, 0}
	written            = promauto.NewCounter(prometheus.CounterOpts{
		Name: "chowder_written_bytes_total",
		Help: "The total number of bytes written to the antivirus",
	})
	read = promauto.NewCounter(prometheus.CounterOpts{
		Name: "chowder_read_bytes_total",
		Help: "The total number of bytes read from the antivirus",
	})
	_ VirusScanner = &ClamAV{}
)

// VirusScanner is the interface for a virus scanning service
type VirusScanner interface {
	Scan(stream io.Reader) (infected bool, msg string, err error)
	Ok() (ok bool, msg string, err error)
}

// ClamAV is a virus scanning service backed by a ClamAV tcp connection
type ClamAV struct {
	connectionString string
	dial             func() (net.Conn, error)
	prefixPool       sync.Pool
	bufferPool       sync.Pool
}

// NewClamAV returns a new ClamAV tcp backed VirusScanner
func NewClamAV(connectionString string) VirusScanner {
	return &ClamAV{
		connectionString: connectionString,
		dial: func() (net.Conn, error) {
			return net.Dial("tcp", connectionString)
		},
		prefixPool: sync.Pool{
			New: func() interface{} {
				n := make([]byte, 4)
				return &n
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				n := make([]byte, 32*1024)
				return &n
			},
		},
	}
}

// Scan streams the supplied io.Reader to the backing ClamAV Antivirus
func (av *ClamAV) Scan(stream io.Reader) (bool, string, error) {
	log.Debug().Msg("performing scan")
	response, err := av.executeCommand(instream, func(c io.Writer) error {
		if err := av.stream(c, stream); err != nil {
			return fmt.Errorf("failed writing scan content: %v", err)
		}
		nw, err := c.Write(emptyChunk)
		if nw > 0 {
			written.Add(float64(nw))
		}
		if err != nil {
			return fmt.Errorf("failed stopping command: %v", err)
		}
		log.Debug().Int("written", nw).Msg("wrote empty chunk")
		return nil
	})
	if err != nil {
		return false, response, err
	}
	return strings.Contains(response, "FOUND"), response, nil
}

// Ok checks that the backing ClamAV Antivirus is healthy
func (av *ClamAV) Ok() (bool, string, error) {
	log.Debug().Msg("pinging daemon")
	response, err := av.executeCommand(ping, nil)
	if err != nil {
		return false, response, err
	}
	return strings.Contains(response, "PONG"), response, nil
}

func (av *ClamAV) executeCommand(command clamCommand, additionalActions func(io.Writer) error) (string, error) {
	c, err := av.dial()
	if err != nil {
		return "", fmt.Errorf("could not connect: %v", err)
	}
	defer c.Close()
	log.Debug().Str("connection", av.connectionString).Msg("connected to clamd")
	wasOk := make(chan bool, 1)
	respErr := make(chan error, 1)
	resp := &strings.Builder{}
	go getResponse(c, resp, wasOk, respErr)
	nw, err := c.Write(command)
	if nw > 0 {
		written.Add(float64(nw))
	}
	if err != nil {
		return "", fmt.Errorf("failed writing command: %v", err)
	}
	log.Debug().Str("command", string(command)).Msg("wrote command")
	if additionalActions != nil {
		if err = additionalActions(c); err != nil {
			return "", err
		}
	}
	log.Debug().Msg("waiting for response")
	err = <-respErr
	if !<-wasOk {
		return "", fmt.Errorf("failed getting response: %v", err)
	}
	log.Debug().Msg("received response")
	return strings.Trim(resp.String(), "\000"), nil
}

func getResponse(from net.Conn, to io.Writer, ok chan bool, err chan error) {
	isOk := false
	respErr := errDeferNoResponse
	defer func() {
		ok <- isOk
		err <- respErr
	}()
	var nr int64
	nr, respErr = io.Copy(to, from)
	if respErr == nil {
		isOk = true
	}
	if nr > 0 {
		read.Add(float64(nr))
	}
}

// Adapted from io.copyBuffer
func (av *ClamAV) stream(dst io.Writer, src io.Reader) (err error) {
	buf := *av.bufferPool.Get().(*[]byte)
	prefix := *av.prefixPool.Get().(*[]byte)
	for {
		nr, er := src.Read(buf)
		log.Debug().Int("read", nr).Int("length", len(buf)).Msg("read buffer")
		if nr > 0 {
			// write big endian size of upcoming chunksize
			binary.BigEndian.PutUint32(prefix, uint32(nr))
			if len(prefix) != 4 {
				panic(fmt.Errorf("always supposed to write 4 bytes but was going to write %v: %v", len(prefix), prefix))
			}
			nw, ew := dst.Write(prefix)
			if nw > 0 {
				written.Add(float64(nw))
			}
			log.Debug().Int("written", nw).Msg("wrote prefix")
			if ew != nil {
				err = ew
				break
			}
			// actually write chunk contents
			nw, ew = dst.Write(buf[0:nr])
			if nw > 0 {
				written.Add(float64(nw))
			}
			log.Debug().Int("written", nw).Msg("wrote chunk")
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	av.bufferPool.Put(&buf)
	av.prefixPool.Put(&prefix)
	return err
}

// clamCommand wraps the ClamAV command into a reusable io.Reader
type clamCommand []byte

func newCommand(command string) clamCommand {
	return []byte("z" + command + "\000")
}
