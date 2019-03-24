package chowder

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	_        io.Reader    = &clamCommand{}
	_        VirusScanner = &ClamAV{}
	instream              = newCommand("INSTREAM")
	ping                  = newCommand("PING")
	noBytes               = []byte{}
	written               = promauto.NewCounter(prometheus.CounterOpts{
		Name: "chowder_written_bytes_total",
		Help: "The total number of bytes written to the antivirus",
	})
	read = promauto.NewCounter(prometheus.CounterOpts{
		Name: "chowder_read_bytes_total",
		Help: "The total number of bytes read from the antivirus",
	})
)

// VirusScanner is the interface for a virus scanning service
type VirusScanner interface {
	Scan(stream io.Reader) (bool, string, error)
	Ok() (bool, string, error)
}

// ClamAV is a virus scanning service backed by a ClamAV tcp connection
type ClamAV struct {
	connectionString string
	prefixPool       sync.Pool
	bufferPool       sync.Pool
}

// NewClamAV returns a new ClamAV tcp backed VirusScanner
func NewClamAV(connectionString string) VirusScanner {
	return &ClamAV{
		connectionString: connectionString,
		prefixPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 4)
			},
		},
		bufferPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},
	}
}

// Scan streams the supplied io.Reader to the backing ClamAV Antivirus
func (av *ClamAV) Scan(stream io.Reader) (bool, string, error) {
	response, err := av.executeCommand(instream, func(c io.Writer) error {
		if err := av.copy(c, stream); err != nil {
			return fmt.Errorf("failed writing scan content: %v", err)
		}
		return nil
	})
	if err != nil {
		return false, response, err
	}
	return strings.Contains(response, "FOUND"), response, nil
}

// Ok checks that the backing ClamAV Antivirus is healthy
func (av *ClamAV) Ok() (bool, string, error) {
	response, err := av.executeCommand(ping, nil)
	if err != nil {
		return false, response, err
	}
	return strings.Contains(response, "PONG"), response, nil
}

func (av *ClamAV) executeCommand(command io.Reader, additionalActions func(io.Writer) error) (string, error) {
	c, err := net.Dial("tcp", av.connectionString)
	if err != nil {
		return "", fmt.Errorf("could not connect: %v", err)
	}
	defer c.Close()
	wasOk := make(chan bool, 1)
	respErr := make(chan error, 1)
	resp := &strings.Builder{}
	go getResponse(c, resp, wasOk, respErr)
	if err = av.copy(c, command); err != nil {
		return "", fmt.Errorf("failed writing command: %v", err)
	}
	if additionalActions != nil {
		if err = additionalActions(c); err != nil {
			return "", err
		}
	}
	nw, err := c.Write(noBytes)
	if nw > 0 {
		written.Add(float64(nw))
	}
	if err != nil {
		return "", fmt.Errorf("failed stopping command: %v", err)
	}
	err = <-respErr
	if !<-wasOk {
		return "", fmt.Errorf("failed getting response: %v", err)
	}
	return resp.String(), nil
}

func getResponse(from net.Conn, to io.Writer, ok chan bool, err chan error) {
	nr, respErr := io.Copy(to, from)
	if nr > 0 {
		read.Add(float64(nr))
	}
	if err != nil {
		ok <- false
		err <- respErr
	}
	ok <- true
	err <- nil
}

// Adapted from io.copyBuffer
func (av *ClamAV) copy(dst io.Writer, src io.Reader) (err error) {
	buf := av.bufferPool.Get().([]byte)
	prefix := av.prefixPool.Get().([]byte)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			// write big endian size of upcoming chunksize
			prefix = prefix[:0]
			binary.BigEndian.PutUint32(prefix, uint32(nr))
			if len(prefix) != 4 {
				panic(fmt.Errorf("always supposed to write 4 bytes but was going to write %v: %v", len(prefix), prefix))
			}
			nw, ew := dst.Write(prefix)
			if nw > 0 {
				written.Add(float64(nw))
			}
			if ew != nil {
				err = ew
				break
			}
			// actually write chunk contents
			nw, ew = dst.Write(buf[0:nr])
			if nw > 0 {
				written.Add(float64(nw))
			}
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
	av.bufferPool.Put(buf[:0])
	av.prefixPool.Put(prefix[:0])
	return err
}

// clamCommand wraps the ClamAV command into a reusable io.Reader
type clamCommand struct {
	bytes []byte
}

func newCommand(command string) io.Reader {
	return &clamCommand{
		bytes: []byte("z" + command + "\000"),
	}
}

func (c *clamCommand) Read(p []byte) (n int, err error) {
	n = copy(p, c.bytes)
	return
}
