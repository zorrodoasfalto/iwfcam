package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/bluenviron/gortsplib/v4/pkg/description"
	"github.com/bluenviron/gortsplib/v4/pkg/format"
	"github.com/bluenviron/gortsplib/v4/pkg/rtptime"
	"github.com/bluenviron/mediacommon/pkg/codecs/h264"
)

type serverHandler struct {
	stream *gortsplib.ServerStream
}

func (h *serverHandler) OnDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx) (*base.Response, *gortsplib.ServerStream, error) {
	log.Printf("RTSP: DESCRIBE path=%q", ctx.Path)

	// This bridge exposes a single stream only. Do not reject by ctx.Path:
	// depending on the RTSP request/library normalization, the same URL can
	// arrive as "cam", "/cam" or another normalized representation.
	if h.stream == nil {
		log.Printf("RTSP: DESCRIBE sem stream inicializado")
		return &base.Response{StatusCode: base.StatusNotFound}, nil, nil
	}

	return &base.Response{StatusCode: base.StatusOK}, h.stream, nil
}

func (h *serverHandler) OnSetup(ctx *gortsplib.ServerHandlerOnSetupCtx) (*base.Response, *gortsplib.ServerStream, error) {
	log.Printf("RTSP: SETUP path=%q", ctx.Path)

	// Single-stream server: any SETUP that reaches this handler uses this stream.
	if h.stream == nil {
		log.Printf("RTSP: SETUP sem stream inicializado")
		return &base.Response{StatusCode: base.StatusNotFound}, nil, nil
	}

	return &base.Response{StatusCode: base.StatusOK}, h.stream, nil
}

func (h *serverHandler) OnPlay(ctx *gortsplib.ServerHandlerOnPlayCtx) (*base.Response, error) {
	log.Printf("RTSP: cliente iniciou PLAY")
	return &base.Response{StatusCode: base.StatusOK}, nil
}

type videoFrame struct {
	expected int
	parts    map[int][]byte
	created  time.Time
}

var imaStepTable = [...]int{
	7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31,
	34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107, 118, 130, 143,
	157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544,
	598, 658, 724, 796, 876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878,
	2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894,
	6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818,
	18500, 20350, 22385, 24623, 27086, 29794, 32767,
}

var imaIndexTable = [...]int{-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8}

func decodeIMAADPCM(block []byte) []int16 {
	if len(block) < 4 {
		return nil
	}

	predictor := int(int16(binary.LittleEndian.Uint16(block[0:2])))
	stepIndex := int(block[2])
	if stepIndex > 88 {
		stepIndex = 88
	}

	out := make([]int16, 0, 1+(len(block)-4)*2)
	out = append(out, int16(predictor))

	decodeNibble := func(code int) {
		step := imaStepTable[stepIndex]
		diff := step >> 3
		if code&1 != 0 {
			diff += step >> 2
		}
		if code&2 != 0 {
			diff += step >> 1
		}
		if code&4 != 0 {
			diff += step
		}
		if code&8 != 0 {
			predictor -= diff
		} else {
			predictor += diff
		}
		if predictor > 32767 {
			predictor = 32767
		} else if predictor < -32768 {
			predictor = -32768
		}

		stepIndex += imaIndexTable[code]
		if stepIndex < 0 {
			stepIndex = 0
		} else if stepIndex > 88 {
			stepIndex = 88
		}
		out = append(out, int16(predictor))
	}

	for _, b := range block[4:] {
		decodeNibble(int(b & 0x0F))
		decodeNibble(int((b >> 4) & 0x0F))
	}

	return out
}

func linearToMuLaw(sample int16) byte {
	const bias = 0x84
	const clip = 32635

	s := int(sample)
	sign := byte(0)
	if s < 0 {
		sign = 0x80
		s = -s
	}
	if s > clip {
		s = clip
	}
	s += bias

	exponent := 7
	mask := 0x4000
	for exponent > 0 && (s&mask) == 0 {
		exponent--
		mask >>= 1
	}
	mantissa := (s >> (exponent + 3)) & 0x0F
	return ^(sign | byte(exponent<<4) | byte(mantissa))
}

func findAnnexBStart(buf []byte) int {
	max := len(buf)
	if max > 12 {
		max = 12
	}
	for i := 0; i+3 <= max; i++ {
		if i+4 <= len(buf) && buf[i] == 0 && buf[i+1] == 0 && buf[i+2] == 0 && buf[i+3] == 1 {
			return i
		}
		if buf[i] == 0 && buf[i+1] == 0 && buf[i+2] == 1 {
			return i
		}
	}
	return -1
}

func getLocalIP(targetIP string) string {
	c, err := net.Dial("udp", targetIP+":1")
	if err != nil {
		return "0.0.0.0"
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type bridgeConfig struct {
	camIP        string
	streamPort   int
	localPort    int
	passwordHash string
	deviceUID    string
	camID        uint32
	cloudHost    string
	mediaTimeout time.Duration
}

type rtspRuntime struct {
	stream      *gortsplib.ServerStream
	videoMedia  *description.Media
	audioMedia  *description.Media
	videoFormat *format.H264
	audioFormat *format.G711
	dump        *os.File
}

func discoverCameraPort(camIP string) (int, error) {
	cmdAddr := &net.UDPAddr{IP: net.ParseIP(camIP), Port: 10104}
	getUDPInfo := []byte("1TEG\x0b\x00\x0c\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

	discConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 10104})
	if err != nil {
		log.Printf("DISC: porta local 10104 ocupada (%v); usando porta aleatoria", err)
		discConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return 0, fmt.Errorf("DISC: nao consegui abrir socket: %w", err)
	}
	defer discConn.Close()

	for attempt := 1; attempt <= 5; attempt++ {
		log.Printf("DISC 1TEG: GET_UDP_INFO tentativa %d -> %s (socket local %s)", attempt, cmdAddr.String(), discConn.LocalAddr())
		_, _ = discConn.WriteToUDP(getUDPInfo, cmdAddr)
		_ = discConn.SetReadDeadline(time.Now().Add(1200 * time.Millisecond))

		b := make([]byte, 2048)
		n, remote, e := discConn.ReadFromUDP(b)
		if e != nil || n < 36 || !remote.IP.Equal(net.ParseIP(camIP)) || string(b[:4]) != "1TEG" {
			continue
		}

		extracted := int(binary.BigEndian.Uint16(b[34:36]))
		if extracted != 0 {
			log.Printf("DISC 1TEG: resposta len=%d de=%s; porta extraida=%d", n, remote.String(), extracted)
			return extracted, nil
		}
		if remote.Port != 10104 {
			log.Printf("DISC 1TEG: usando porta de origem da resposta=%d", remote.Port)
			return remote.Port, nil
		}
	}

	return 0, fmt.Errorf("DISC 1TEG: nao consegui descobrir a porta UDP da camera")
}

func runCameraSession(cfg bridgeConfig, media *rtspRuntime, stop <-chan struct{}) error {
	cameraPort := cfg.streamPort
	if cameraPort == 0 {
		p, err := discoverCameraPort(cfg.camIP)
		if err != nil {
			return err
		}
		cameraPort = p
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: cfg.localPort})
	if err != nil {
		log.Printf("SESSION: UDP local %d ocupado (%v); usando porta aleatoria", cfg.localPort, err)
		conn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return fmt.Errorf("abrindo socket UDP: %w", err)
		}
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(8 * 1024 * 1024)

	actualLocalPort := conn.LocalAddr().(*net.UDPAddr).Port
	localIP := getLocalIP(cfg.camIP)
	camAddr := &net.UDPAddr{IP: net.ParseIP(cfg.camIP), Port: cameraPort}

	log.Printf("SESSION: UDP=%s:%d camera=%s", localIP, actualLocalPort, camAddr)

	sendPacket := func(label string, p []byte) {
		if _, err := conn.WriteToUDP(p, camAddr); err != nil {
			log.Printf("TX %s error: %v", label, err)
		}
	}

	connectReq := []byte{
		0x32, 0x54, 0x45, 0x47, 0x01, 0x00, 0x14, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	afterPreflight := func() {
		log.Printf("FLOW: preflight concluido -> prime direto x2")
		sendPacket("connect prime #1", connectReq)
		time.Sleep(3 * time.Millisecond)
		sendPacket("connect prime #2", connectReq)
	}

	sess, err := cloudSetup(
		conn,
		net.ParseIP(localIP),
		actualLocalPort,
		cfg.camID,
		cfg.deviceUID,
		cfg.passwordHash,
		cfg.cloudHost,
		afterPreflight,
	)
	if err != nil {
		return fmt.Errorf("CLOUD: %w", err)
	}

	sessionID := sess.RelayID
	if sessionID == 0 {
		sessionID = 1
	}
	log.Printf("P2P: sessionID=%d clientID=0x%08x camID=0x%08x", sessionID, sess.ClientID, sess.CamID)

	buildControl := func(cmd uint32, arg uint32) []byte {
		b := make([]byte, 28)
		copy(b[0:4], "2TEG")
		binary.LittleEndian.PutUint16(b[4:6], 1)
		binary.LittleEndian.PutUint16(b[6:8], 20)
		binary.LittleEndian.PutUint32(b[8:12], sessionID)
		binary.LittleEndian.PutUint32(b[12:16], cmd)
		binary.LittleEndian.PutUint32(b[16:20], arg)
		return b
	}

	buildStreamMode := func(mode uint32) []byte {
		b := make([]byte, 36)
		copy(b[0:4], "2TEG")
		binary.LittleEndian.PutUint16(b[4:6], 1)
		binary.LittleEndian.PutUint16(b[6:8], 28)
		binary.LittleEndian.PutUint32(b[8:12], sessionID)
		binary.LittleEndian.PutUint32(b[12:16], 0)
		binary.LittleEndian.PutUint32(b[16:20], 1)
		binary.LittleEndian.PutUint32(b[20:24], 8)
		binary.LittleEndian.PutUint32(b[32:36], mode)
		return b
	}

	directInner0 := func() []byte {
		b := []byte{
			0x32, 0x54, 0x45, 0x47, 0x01, 0x00, 0x1c, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		binary.LittleEndian.PutUint32(b[8:12], sessionID)
		return b
	}

	directBootstrap := [][]byte{
		directInner0(),
		buildControl(13, 1),
		buildControl(14, 2),
		buildControl(15, 0),
		buildControl(15, 2),
		buildControl(21, 0),
	}

	query19 := buildControl(19, 1)
	query26 := buildControl(26, 0)
	keepalive0 := buildControl(15, 0)
	keepalive2 := buildControl(15, 2)
	closeSession := buildControl(3, 1)
	startStream := buildStreamMode(3)
	stopStream := buildStreamMode(0)

	bootstrapSent := false
	sendDirectBootstrap := func() {
		if bootstrapSent {
			return
		}
		bootstrapSent = true
		log.Printf("DIRECT BOOTSTRAP: enviando para %s", camAddr)

		for _, p := range directBootstrap {
			sendPacket("bootstrap", p)
			time.Sleep(20 * time.Millisecond)
		}
		sendPacket("query19", query19)
		time.Sleep(20 * time.Millisecond)
		sendPacket("query26", query26)
		time.Sleep(20 * time.Millisecond)
		sendPacket("start stream", startStream)
		log.Printf("DIRECT BOOTSTRAP: START_STREAM mode=3 enviado")
	}

	helloReq := make([]byte, 32)
	copy(helloReq[0:4], "2TEG")
	binary.LittleEndian.PutUint16(helloReq[4:6], 0)
	binary.LittleEndian.PutUint16(helloReq[6:8], 24)
	binary.LittleEndian.PutUint32(helloReq[8:12], 0)
	binary.LittleEndian.PutUint32(helloReq[12:16], 10)
	binary.LittleEndian.PutUint32(helloReq[16:20], 1)
	binary.LittleEndian.PutUint32(helloReq[20:24], sess.ClientID)
	binary.LittleEndian.PutUint32(helloReq[28:32], sess.CamID)

	ready := false
	sawStage1 := false
	helloAttempts := 0
	bufHS := make([]byte, 4096)
	hsDeadline := time.Now().Add(8 * time.Second)
	nextHello := time.Time{}

	for !ready && time.Now().Before(hsDeadline) {
		select {
		case <-stop:
			return fmt.Errorf("encerrando")
		default:
		}

		if !sawStage1 && helloAttempts < 4 && (nextHello.IsZero() || time.Now().After(nextHello)) {
			helloAttempts++
			log.Printf("P2P: hello stage=0 counter=10 tentativa=%d", helloAttempts)
			sendPacket("hello", helloReq)
			nextHello = time.Now().Add(1200 * time.Millisecond)
		}

		readUntil := time.Now().Add(450 * time.Millisecond)
		if readUntil.After(hsDeadline) {
			readUntil = hsDeadline
		}
		_ = conn.SetReadDeadline(readUntil)

		n, remote, e := conn.ReadFromUDP(bufHS)
		if e != nil {
			continue
		}
		if !remote.IP.Equal(net.ParseIP(cfg.camIP)) || n < 32 || string(bufHS[:4]) != "2TEG" {
			continue
		}
		if binary.LittleEndian.Uint16(bufHS[4:6]) != 0 {
			continue
		}

		stage := binary.LittleEndian.Uint32(bufHS[8:12])
		counter := binary.LittleEndian.Uint32(bufHS[12:16])
		log.Printf("P2P RX: stage=%d counter=%d", stage, counter)

		if stage == 1 {
			sawStage1 = true
			echo := append([]byte(nil), bufHS[:n]...)
			_, _ = conn.WriteToUDP(echo, camAddr)

			if counter == 9 && !bootstrapSent {
				sendDirectBootstrap()
			}
			continue
		}

		if stage == 2 {
			ready = true
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	if !ready {
		return fmt.Errorf("P2P: handshake direto nao concluiu")
	}
	log.Printf("P2P: handshake concluido")

	if !bootstrapSent {
		sendDirectBootstrap()
	}

	keepaliveDone := make(chan struct{})
	go func() {
		t2 := time.NewTicker(2 * time.Second)
		t0 := time.NewTicker(3 * time.Second)
		defer t2.Stop()
		defer t0.Stop()

		for {
			select {
			case <-t2.C:
				sendPacket("keepalive f/2", keepalive2)
			case <-t0.C:
				sendPacket("keepalive f/0", keepalive0)
			case <-keepaliveDone:
				return
			case <-stop:
				return
			}
		}
	}()
	defer close(keepaliveDone)

	defer func() {
		log.Printf("SESSION: stop/close da sessao P2P")
		for i := 0; i < 2; i++ {
			sendPacket("stop stream", stopStream)
			time.Sleep(15 * time.Millisecond)
		}
		for i := 0; i < 2; i++ {
			sendPacket("close session", closeSession)
			time.Sleep(10 * time.Millisecond)
		}
	}()

	videoEncoder, err := media.videoFormat.CreateEncoder()
	if err != nil {
		return fmt.Errorf("video encoder: %w", err)
	}
	audioEncoder, err := media.audioFormat.CreateEncoder()
	if err != nil {
		return fmt.Errorf("audio encoder: %w", err)
	}
	videoTime := &rtptime.Encoder{ClockRate: media.videoFormat.ClockRate()}
	if err := videoTime.Initialize(); err != nil {
		return fmt.Errorf("rtptime: %w", err)
	}
	sessionStart := time.Now()
	var audioTimestamp uint32

	ackFPS := byte(1)
	fpsWindowStart := time.Now()
	fpsFrames := 0

	updateFPS := func() {
		fpsFrames++
		elapsed := time.Since(fpsWindowStart)
		if elapsed >= time.Second {
			fps := int(float64(fpsFrames)/elapsed.Seconds() + 0.5)
			if fps < 1 {
				fps = 1
			}
			if fps > 255 {
				fps = 255
			}
			ackFPS = byte(fps)
			fpsFrames = 0
			fpsWindowStart = time.Now()
		}
	}

	sendAck := func(frameID uint16) {
		ack := []byte{
			0x32, 0x54, 0x45, 0x47, 0x04, 0x00, 0x10, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01,
			0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
		}
		binary.LittleEndian.PutUint32(ack[8:12], sessionID)
		ack[12] = ackFPS
		binary.LittleEndian.PutUint16(ack[20:22], frameID)
		_, _ = conn.WriteToUDP(ack, camAddr)
	}

	frames := make(map[uint16]*videoFrame)
	var sps, pps []byte
	lastGoodVideo := time.Now()
	lastStatus := time.Now()
	buf := make([]byte, 65535)

	log.Printf("RECOVERY: monitor interno ativo; timeout H264=%s", cfg.mediaTimeout)

	for {
		select {
		case <-stop:
			return fmt.Errorf("encerrando")
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if time.Since(lastGoodVideo) > cfg.mediaTimeout {
					return fmt.Errorf("sem H264 valido por %s", time.Since(lastGoodVideo).Round(time.Second))
				}
				continue
			}
			return fmt.Errorf("UDP RX: %w", err)
		}

		if !remote.IP.Equal(net.ParseIP(cfg.camIP)) || n < 24 || string(buf[:4]) != "2TEG" {
			continue
		}
		if binary.LittleEndian.Uint16(buf[4:6]) != 3 {
			continue
		}

		dataLen := int(binary.LittleEndian.Uint16(buf[6:8]))
		frameIndex := binary.LittleEndian.Uint16(buf[16:18])
		packetIndex := int(binary.LittleEndian.Uint16(buf[18:20]))
		payloadLen := int(binary.LittleEndian.Uint32(buf[20:24]))
		offset := 8 + dataLen - payloadLen
		if payloadLen <= 0 || offset < 24 || offset+payloadLen > n {
			continue
		}

		payload := append([]byte(nil), buf[offset:offset+payloadLen]...)

		if packetIndex == 0 && offset == 28 && payloadLen == 516 {
			pcm := decodeIMAADPCM(payload)
			if len(pcm) != 0 {
				mulaw := make([]byte, len(pcm))
				for i, sample := range pcm {
					mulaw[i] = linearToMuLaw(sample)
				}
				pkts, encErr := audioEncoder.Encode(mulaw)
				if encErr == nil {
					for _, pkt := range pkts {
						pkt.Timestamp += audioTimestamp
						_ = media.stream.WritePacketRTP(media.audioMedia, pkt)
					}
					audioTimestamp += uint32(len(mulaw))
				}
			}
			sendAck(frameIndex)
			continue
		}

		vf, ok := frames[frameIndex]
		if !ok {
			vf = &videoFrame{parts: make(map[int][]byte), created: time.Now()}
			frames[frameIndex] = vf
		}
		vf.parts[packetIndex] = payload

		if packetIndex == 0 && offset >= 40 {
			expected := int(binary.LittleEndian.Uint32(buf[28:32]))
			width := int(binary.LittleEndian.Uint16(buf[32:34]))
			height := int(binary.LittleEndian.Uint16(buf[34:36]))
			if expected > 0 && expected < 100 && width >= 160 && width <= 4096 && height >= 120 && height <= 2160 {
				vf.expected = expected
			}
		}

		if vf.expected > 0 && len(vf.parts) >= vf.expected {
			keys := make([]int, 0, vf.expected)
			complete := true
			for i := 0; i < vf.expected; i++ {
				if _, exists := vf.parts[i]; !exists {
					complete = false
					break
				}
				keys = append(keys, i)
			}

			if complete {
				sort.Ints(keys)
				assembled := make([]byte, 0)
				for _, k := range keys {
					assembled = append(assembled, vf.parts[k]...)
				}

				start := findAnnexBStart(assembled)
				if start >= 0 {
					annexb := assembled[start:]
					au, decErr := h264.AnnexBUnmarshal(annexb)
					if decErr == nil && len(au) > 0 {
						for _, nalu := range au {
							if len(nalu) == 0 {
								continue
							}
							switch nalu[0] & 0x1F {
							case 7:
								sps = append([]byte(nil), nalu...)
							case 8:
								pps = append([]byte(nil), nalu...)
							}
						}
						if sps != nil && pps != nil {
							media.videoFormat.SafeSetParams(sps, pps)
						}
						if media.dump != nil {
							_, _ = media.dump.Write(annexb)
						}

						pkts, encErr := videoEncoder.Encode(au)
						if encErr == nil {
							ts := videoTime.Encode(time.Since(sessionStart))
							for _, pkt := range pkts {
								pkt.Timestamp = ts
								_ = media.stream.WritePacketRTP(media.videoMedia, pkt)
							}

							wasStale := time.Since(lastGoodVideo) > 2*time.Second
							lastGoodVideo = time.Now()
							if wasStale {
								log.Printf("MEDIA: H264 voltou a ser publicado")
							}
						}
					}
				}
			}

			updateFPS()
			sendAck(frameIndex)
			delete(frames, frameIndex)
		}

		cutoff := time.Now().Add(-2 * time.Second)
		for id, fr := range frames {
			if fr.created.Before(cutoff) {
				delete(frames, id)
			}
		}

		if time.Since(lastStatus) > 10*time.Second {
			log.Printf("STATUS: ultimo H264 valido ha %s; pendingFrames=%d",
				time.Since(lastGoodVideo).Round(time.Second), len(frames))
			lastStatus = time.Now()
		}

		if time.Since(lastGoodVideo) > cfg.mediaTimeout {
			return fmt.Errorf("sem H264 valido por %s", time.Since(lastGoodVideo).Round(time.Second))
		}
	}
}

func main() {
	var camIP string
	var streamPort int
	var localPort int
	var rtspPort string
	var dumpPath string
	var passwordHash string
	var deviceUID string
	var camIDText string
	var cloudHost string
	var mediaTimeoutSec int
	var reconnectDelaySec int

	flag.StringVar(&camIP, "ip", "172.16.0.221", "camera IP")
	flag.IntVar(&streamPort, "stream-port", 0, "camera proprietary UDP stream port (0 = auto-discover on every reconnect)")
	flag.IntVar(&localPort, "local-port", 36891, "local UDP source port used by iWFCam")
	flag.StringVar(&rtspPort, "rtsp-port", "8554", "local RTSP port")
	flag.StringVar(&dumpPath, "dump", "", "optional raw H264 dump file")
	flag.StringVar(&passwordHash, "password-hash", "6ddd60335190", "12-char iWFCam device password token")
	flag.StringVar(&deviceUID, "uid", "TKB7E73-7DCD145AC932-0677A0", "iWFCam device UID")
	flag.StringVar(&camIDText, "cam-id", "0x00468e3f", "camera cloud ID")
	flag.StringVar(&cloudHost, "cloud", "cloud.ismartol.com:10102", "iWFCam cloud rendezvous host")
	flag.IntVar(&mediaTimeoutSec, "media-timeout", 15, "seconds without a valid H264 frame before an internal P2P reconnect")
	flag.IntVar(&reconnectDelaySec, "reconnect-delay", 3, "seconds between internal reconnect attempts")
	flag.Parse()

	camID, err := parseUint32Auto(camIDText)
	if err != nil {
		log.Fatalf("cam-id invalido: %v", err)
	}
	if mediaTimeoutSec < 5 {
		mediaTimeoutSec = 5
	}
	if reconnectDelaySec < 1 {
		reconnectDelaySec = 1
	}

	log.Printf("IWFCam H264 bridge V17 self-healing: camera=%s", camIP)

	server := &gortsplib.Server{RTSPAddress: ":" + rtspPort}
	handler := &serverHandler{}
	server.Handler = handler
	if err := server.Start(); err != nil {
		log.Fatalf("RTSP server: %v", err)
	}
	defer server.Close()

	videoFormat := &format.H264{PayloadTyp: 96, PacketizationMode: 1}
	audioFormat := &format.G711{PayloadTyp: 0, MULaw: true, SampleRate: 8000, ChannelCount: 1}
	videoMedia := &description.Media{Type: description.MediaTypeVideo, Formats: []format.Format{videoFormat}}
	audioMedia := &description.Media{Type: description.MediaTypeAudio, Formats: []format.Format{audioFormat}}
	desc := &description.Session{Medias: []*description.Media{videoMedia, audioMedia}}

	stream := gortsplib.NewServerStream(server, desc)
	defer stream.Close()
	handler.stream = stream

	var dump *os.File
	if dumpPath != "" {
		dump, err = os.OpenFile(dumpPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Fatal(err)
		}
		defer dump.Close()
	}

	media := &rtspRuntime{
		stream:      stream,
		videoMedia:  videoMedia,
		audioMedia:  audioMedia,
		videoFormat: videoFormat,
		audioFormat: audioFormat,
		dump:        dump,
	}

	cfg := bridgeConfig{
		camIP:        camIP,
		streamPort:   streamPort,
		localPort:    localPort,
		passwordHash: passwordHash,
		deviceUID:    deviceUID,
		camID:        camID,
		cloudHost:    cloudHost,
		mediaTimeout: time.Duration(mediaTimeoutSec) * time.Second,
	}

	log.Printf("RTSP: rtsp://127.0.0.1:%s/cam", rtspPort)
	log.Printf("RECOVERY: RTSP fica ativo; somente a sessao camera/P2P sera renegociada")
	log.Printf("RECOVERY: media-timeout=%ds reconnect-delay=%ds", mediaTimeoutSec, reconnectDelaySec)

	stop := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stop)
	}()

	attempt := 0
	for {
		select {
		case <-stop:
			log.Printf("SHUTDOWN: encerrando bridge")
			return
		default:
		}

		attempt++
		log.Printf("SESSION: iniciando/renegociando #%d", attempt)

		err := runCameraSession(cfg, media, stop)
		if err != nil {
			select {
			case <-stop:
				log.Printf("SHUTDOWN: sessao encerrada")
				return
			default:
			}
			log.Printf("RECOVERY: sessao caiu: %v", err)
		}

		log.Printf("RECOVERY: tentando novamente em %ds; RTSP continua na porta %s", reconnectDelaySec, rtspPort)
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(reconnectDelaySec) * time.Second):
		}
	}
}
