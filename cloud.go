package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

type cloudSession struct {
	Server         *net.UDPAddr
	ClientID       uint32
	CamID          uint32
	CamPublicIP    net.IP
	CamPublicPort  uint16
	SelfPublicIP   net.IP
	SelfPublicPort uint16
	RelayID        uint32
}

func parseUint32Auto(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.TrimSpace(s), 0, 32)
	return uint32(v), err
}

func buildCloudProbe(localIP net.IP, localPort int, camID, clientID uint32) ([]byte, error) {
	ip4 := localIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv4 local invalido: %v", localIP)
	}
	// Captured iWFCam preflight:
	// 1TEG cmd=3, len=32, constant=1, clientID, 0, camID, LAN IP, LAN UDP port.
	b := make([]byte, 40)
	copy(b[0:4], "1TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0x0003)
	binary.LittleEndian.PutUint16(b[6:8], 32)
	binary.LittleEndian.PutUint32(b[8:12], 1)
	binary.LittleEndian.PutUint32(b[12:16], clientID)
	binary.LittleEndian.PutUint32(b[16:20], 0)
	binary.LittleEndian.PutUint32(b[20:24], camID)
	copy(b[24:28], ip4)
	binary.BigEndian.PutUint16(b[28:30], uint16(localPort))
	return b, nil
}

func buildZeroTEGLookup(uid string) []byte {
	b := make([]byte, 108)
	copy(b[0:4], "0TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0)
	binary.LittleEndian.PutUint16(b[6:8], 100)
	binary.LittleEndian.PutUint32(b[8:12], 1)
	copy(b[12:44], []byte(uid))
	// Exact marker seen in the app capture.
	b[76] = 0x42
	b[77] = 0x52
	return b
}

func buildCloudRegister(localIP net.IP, localPort int, camID uint32, uid, hash string) ([]byte, error) {
	ip4 := localIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("IPv4 local invalido: %v", localIP)
	}
	if len(hash) != 12 {
		return nil, fmt.Errorf("password hash precisa ter 12 chars")
	}
	if len(uid) > 32 {
		return nil, fmt.Errorf("UID muito grande")
	}
	b := make([]byte, 148)
	copy(b[0:4], "1TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0x0000)
	binary.LittleEndian.PutUint16(b[6:8], 140)
	binary.LittleEndian.PutUint32(b[8:12], 1)
	binary.LittleEndian.PutUint32(b[20:24], camID)
	copy(b[24:28], ip4)
	binary.BigEndian.PutUint16(b[30:32], uint16(localPort))
	copy(b[32:64], []byte(uid))
	b[64] = 0x09
	copy(b[65:77], []byte(hash))
	b[80] = 0x01
	b[82] = 0xaa
	b[83] = 0xcc
	return b, nil
}

func buildCloudConnect(sess cloudSession, localIP net.IP, localPort int, hash string) []byte {
	b := make([]byte, 48)
	copy(b[0:4], "1TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0x0004)
	binary.LittleEndian.PutUint16(b[6:8], 40)
	binary.LittleEndian.PutUint32(b[8:12], sess.ClientID)
	binary.LittleEndian.PutUint32(b[16:20], sess.CamID)
	copy(b[20:24], sess.SelfPublicIP.To4())
	binary.BigEndian.PutUint16(b[24:26], sess.SelfPublicPort)
	binary.BigEndian.PutUint16(b[26:28], uint16(localPort))
	copy(b[28:32], localIP.To4())
	b[32] = 0x09
	copy(b[33:45], []byte(hash))
	return b
}

func buildCloudPunch(sess cloudSession) []byte {
	b := make([]byte, 32)
	copy(b[0:4], "1TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0x0006)
	binary.LittleEndian.PutUint16(b[6:8], 24)
	copy(b[8:12], sess.CamPublicIP.To4())
	binary.BigEndian.PutUint16(b[12:14], sess.CamPublicPort)
	binary.LittleEndian.PutUint16(b[14:16], 10)
	binary.LittleEndian.PutUint32(b[16:20], 1)
	binary.LittleEndian.PutUint32(b[20:24], sess.ClientID)
	binary.LittleEndian.PutUint32(b[28:32], sess.CamID)
	return b
}

func buildRelay(sess cloudSession, inner []byte) []byte {
	b := make([]byte, 28+len(inner))
	copy(b[0:4], "1TEG")
	binary.LittleEndian.PutUint16(b[4:6], 0x0009)
	binary.LittleEndian.PutUint16(b[6:8], uint16(20+len(inner)))
	binary.LittleEndian.PutUint32(b[8:12], sess.ClientID)
	relayID := sess.RelayID
	if relayID == 0 {
		relayID = 1
	}
	binary.LittleEndian.PutUint32(b[12:16], relayID)
	copy(b[16:20], sess.CamPublicIP.To4())
	binary.BigEndian.PutUint16(b[20:22], sess.CamPublicPort)
	binary.LittleEndian.PutUint32(b[24:28], uint32(len(inner)))
	copy(b[28:], inner)
	return b
}

func parseCloudSessionPacket(p []byte, remote *net.UDPAddr) (cloudSession, bool) {
	if len(p) < 160 || string(p[:4]) != "1TEG" || binary.LittleEndian.Uint16(p[4:6]) != 2 {
		return cloudSession{}, false
	}
	s := cloudSession{
		Server:         &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port},
		ClientID:       binary.LittleEndian.Uint32(p[8:12]),
		CamID:          binary.LittleEndian.Uint32(p[16:20]),
		CamPublicIP:    net.IPv4(p[72], p[73], p[74], p[75]),
		CamPublicPort:  binary.BigEndian.Uint16(p[76:78]),
		SelfPublicIP:   net.IPv4(p[84], p[85], p[86], p[87]),
		SelfPublicPort: binary.BigEndian.Uint16(p[88:90]),
	}
	if s.ClientID == 0 || s.CamID == 0 || s.CamPublicPort == 0 || s.SelfPublicPort == 0 {
		return cloudSession{}, false
	}
	return s, true
}

func relayInner0(stage uint32) []byte {
	b := []byte{
		0x32, 0x54, 0x45, 0x47, 0x01, 0x00, 0x1c, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
	}
	binary.LittleEndian.PutUint32(b[8:12], stage)
	return b
}

func relayControl(stage uint32, cmd uint32, arg uint32) []byte {
	b := make([]byte, 28)
	copy(b[0:4], "2TEG")
	binary.LittleEndian.PutUint16(b[4:6], 1)
	binary.LittleEndian.PutUint16(b[6:8], 20)
	binary.LittleEndian.PutUint32(b[8:12], stage)
	binary.LittleEndian.PutUint32(b[12:16], cmd)
	binary.LittleEndian.PutUint32(b[16:20], arg)
	return b
}

func sendRelayBootstrap(conn *net.UDPConn, sess cloudSession) {
	stage := sess.RelayID
	if stage == 0 {
		stage = 1
	}
	seq := [][]byte{
		relayInner0(stage),
		relayControl(stage, 13, 1),
		relayControl(stage, 14, 2),
		relayControl(stage, 15, 0),
		relayControl(stage, 15, 2),
		relayControl(stage, 21, 0),
	}
	labels := []string{"cmd0", "cmd13", "cmd14", "cmd15a0", "cmd15a2", "cmd21"}
	for i, inner := range seq {
		_, _ = conn.WriteToUDP(buildRelay(sess, inner), sess.Server)
		log.Printf("CLOUD: relay bootstrap %s enviado (relayID=%d innerStage=%d)", labels[i], sess.RelayID, stage)
		if i != len(seq)-1 {
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func cloudCandidates(host string) []*net.UDPAddr {
	seen := map[string]bool{}
	var out []*net.UDPAddr
	add := func(ip net.IP) {
		if ip == nil || ip.To4() == nil {
			return
		}
		s := ip.String()
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, &net.UDPAddr{IP: ip.To4(), Port: 10102})
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		if ips, err := net.LookupIP(h); err == nil {
			for _, ip := range ips {
				add(ip)
			}
		}
	}
	// Addresses observed in the capture.
	for _, s := range []string{"47.251.51.63", "47.105.83.157", "8.216.32.7"} {
		add(net.ParseIP(s))
	}
	return out
}

func cloudSetup(conn *net.UDPConn, localIP net.IP, localPort int, camID uint32, uid, hash, host string, afterPreflight func()) (cloudSession, error) {
	cands := cloudCandidates(host)
	if len(cands) == 0 {
		return cloudSession{}, fmt.Errorf("nenhum servidor cloud resolvido")
	}
	buf := make([]byte, 4096)

	// V8: the real app does this cmd=3 preflight BEFORE registration.
	// The earlier bridge skipped it, and the cloud ignored the registration.
	const capturedClientID uint32 = 0x00108a82
	probe, err := buildCloudProbe(localIP, localPort, camID, capturedClientID)
	if err != nil {
		return cloudSession{}, err
	}
	log.Printf("CLOUD: preflight cmd3 clientID=0x%08x em %d servidor(es)", capturedClientID, len(cands))
	for _, a := range cands {
		log.Printf("CLOUD: PREFLIGHT -> %s", a)
		_, _ = conn.WriteToUDP(probe, a)
	}

	var preferred *net.UDPAddr
	var preflightSess cloudSession
	deadline := time.Now().Add(1800 * time.Millisecond)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, remote, e := conn.ReadFromUDP(buf)
		if e != nil {
			break
		}
		if n < 8 {
			continue
		}
		prefix := string(buf[:4])
		if prefix == "1TEG" {
			cmd := binary.LittleEndian.Uint16(buf[4:6])
			log.Printf("CLOUD PREFLIGHT RX: %s cmd=%d len=%d hex=%x", remote, cmd, n, buf[:minInt(n, 64)])
			if cmd == 2 && n >= 160 {
				if ps, ok := parseCloudSessionPacket(buf[:n], remote); ok {
					if preferred == nil {
						preferred = &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: remote.Port}
						preflightSess = ps
						log.Printf("CLOUD: sessao valida no preflight: server=%s clientID=0x%08x camID=0x%08x camPublic=%s:%d selfPublic=%s:%d",
							ps.Server, ps.ClientID, ps.CamID, ps.CamPublicIP, ps.CamPublicPort, ps.SelfPublicIP, ps.SelfPublicPort)
					}
				}
			}
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	// PCAP order: the app primes the direct camera peer only AFTER the cloud preflight
	// has returned a valid session, and BEFORE the 0TEG directory/REG/CONNECT phase.
	if afterPreflight != nil {
		afterPreflight()
	}

	// The app also asks the 0TEG directory servers before registration.
	lookup := buildZeroTEGLookup(uid)
	for _, s := range []string{"47.105.85.47", "47.254.26.168", "47.251.51.63", "8.216.32.7"} {
		a := &net.UDPAddr{IP: net.ParseIP(s), Port: 10101}
		_, _ = conn.WriteToUDP(lookup, a)
		log.Printf("CLOUD: 0TEG lookup -> %s", a)
	}
	// Drain a few directory replies so they don't contaminate the next phase.
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, remote, e := conn.ReadFromUDP(buf)
		if e != nil {
			break
		}
		if n >= 8 {
			log.Printf("CLOUD DIR RX: %s prefix=%q len=%d", remote, string(buf[:4]), n)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	req, err := buildCloudRegister(localIP, localPort, camID, uid, hash)
	if err != nil {
		return cloudSession{}, err
	}

	// Once preflight returned a full valid session, that server is authoritative.
	// Do NOT fan REG out to the other cloud servers: one of them can return a
	// syntactically long (168-byte) packet with bogus endpoint fields and poison
	// the active session (observed: camPublic=255.0.0.0:65280).
	var ordered []*net.UDPAddr
	if preferred != nil {
		ordered = append(ordered, &net.UDPAddr{IP: append(net.IP(nil), preferred.IP...), Port: 10102})
		log.Printf("CLOUD: preflight escolheu servidor autoritativo %s; REG sera enviado somente a ele", ordered[0])
	} else {
		ordered = append(ordered, cands...)
	}

	log.Printf("CLOUD: registrando UID=%s camID=0x%08x em %d servidor(es)", uid, camID, len(ordered))
	for _, a := range ordered {
		log.Printf("CLOUD: REG -> %s", a)
		_, _ = conn.WriteToUDP(req, a)
	}

	deadline = time.Now().Add(750 * time.Millisecond)
	_ = conn.SetReadDeadline(deadline)
	var sess cloudSession
	for time.Now().Before(deadline) {
		n, remote, e := conn.ReadFromUDP(buf)
		if e != nil {
			break
		}
		if n < 8 {
			continue
		}
		if string(buf[:4]) != "1TEG" {
			log.Printf("CLOUD REG RX estranho: %s prefix=%q len=%d", remote, string(buf[:4]), n)
			continue
		}
		cmd := binary.LittleEndian.Uint16(buf[4:6])
		log.Printf("CLOUD REG RX: %s cmd=%d len=%d hex=%x", remote, cmd, n, buf[:minInt(n, 64)])
		if cmd != 2 || n < 160 {
			continue
		}
		if rs, ok := parseCloudSessionPacket(buf[:n], remote); ok {
			if preflightSess.Server != nil {
				// The full preflight response already gave us the correct clientID,
				// camID and public endpoints. Keep it authoritative. REG is only
				// acknowledgement/continuation in the captures we are reproducing.
				log.Printf("CLOUD: REG longo recebido de %s, mas mantendo sessao autoritativa do PREFLIGHT", remote)
				log.Printf("CLOUD: REG candidato clientID=0x%08x camID=0x%08x camPublic=%s:%d selfPublic=%s:%d",
					rs.ClientID, rs.CamID, rs.CamPublicIP, rs.CamPublicPort, rs.SelfPublicIP, rs.SelfPublicPort)
				continue
			}
			sess = rs
			log.Printf("CLOUD: escolhido pelo REG=%s clientID=0x%08x camID=0x%08x camPublic=%s:%d selfPublic=%s:%d",
				remote, sess.ClientID, sess.CamID, sess.CamPublicIP, sess.CamPublicPort, sess.SelfPublicIP, sess.SelfPublicPort)
			break
		}
	}
	if preflightSess.Server != nil {
		sess = preflightSess
		log.Printf("CLOUD: usando sessao autoritativa do PREFLIGHT")
		log.Printf("CLOUD: escolhido=%s clientID=0x%08x camID=0x%08x camPublic=%s:%d selfPublic=%s:%d",
			sess.Server, sess.ClientID, sess.CamID, sess.CamPublicIP, sess.CamPublicPort, sess.SelfPublicIP, sess.SelfPublicPort)
	}
	if sess.Server == nil {
		_ = conn.SetReadDeadline(time.Time{})
		return sess, fmt.Errorf("sem sessao cloud valida")
	}

	c4 := buildCloudConnect(sess, localIP, localPort, hash)
	_, _ = conn.WriteToUDP(c4, sess.Server)
	log.Printf("CLOUD: CONNECT cmd4 -> %s", sess.Server)

	sentPunch := false
	sentRelayInitial := false
	sentBootstrap := false // V15: intentionally remains false; direct bootstrap is in main.go

	// The working iWFCam capture performs this phase very quickly:
	// first relayed packet -> initial relay reply; cmd5 -> NAT punch;
	// server cmd6 -> relay bootstrap burst; direct 2TEG hello starts ~20ms later.
	deadline = time.Now().Add(1400 * time.Millisecond)
	_ = conn.SetReadDeadline(deadline)
	for time.Now().Before(deadline) {
		n, remote, e := conn.ReadFromUDP(buf)
		if e != nil {
			break
		}
		if n < 8 {
			continue
		}

		// Do not silently eat direct-camera 2TEG traffic here.
		// In the real app, the direct handshake starts only after the relay bootstrap.
		if string(buf[:4]) == "2TEG" {
			log.Printf("CLOUD: direct 2TEG chegou cedo de %s len=%d; encerrando fase cloud", remote, n)
			break
		}
		if string(buf[:4]) != "1TEG" {
			continue
		}

		cmd := binary.LittleEndian.Uint16(buf[4:6])
		log.Printf("CLOUD RX: %s cmd=%d len=%d hex=%x", remote, cmd, n, buf[:minInt(n, 64)])

		if cmd == 9 && n >= 28 {
			rid := binary.LittleEndian.Uint32(buf[12:16])
			if rid != 0 && sess.RelayID == 0 {
				sess.RelayID = rid
				log.Printf("CLOUD: relayID dinamico=%d", sess.RelayID)
			}
			if !sentRelayInitial {
				_, _ = conn.WriteToUDP(buildRelay(sess, relayInner0(func() uint32 {
					if sess.RelayID != 0 {
						return sess.RelayID
					}
					return 1
				}())), sess.Server)
				sentRelayInitial = true
				log.Printf("CLOUD: relay inicial enviado (relayID=%d)", sess.RelayID)
			}
		}

		if cmd == 5 && !sentPunch {
			punch := buildCloudPunch(sess)
			_, _ = conn.WriteToUDP(punch, sess.Server)
			sentPunch = true
			log.Printf("CLOUD: NAT punch cmd6 enviado")
		}

		if cmd == 6 {
			// V15: cmd6 only completes the cloud rendezvous/NAT-punch phase.
			// The AVAPI/bootstrap packets are NOT sent through the cloud relay.
			// They are sent directly to the camera socket by main.go after
			// stage1/counter9 is observed on the direct P2P path.
			log.Printf("CLOUD: cmd6 recebido; rendezvous concluido, bootstrap ficara no socket direto")
			break
		}
	}

	if !sentPunch {
		_, _ = conn.WriteToUDP(buildCloudPunch(sess), sess.Server)
		log.Printf("CLOUD: NAT punch cmd6 enviado (fallback)")
	}
	if sess.RelayID == 0 {
		sess.RelayID = 1
		log.Printf("CLOUD: relayID nao veio do servidor; usando fallback=1")
	}
	if !sentRelayInitial {
		_, _ = conn.WriteToUDP(buildRelay(sess, relayInner0(func() uint32 {
			if sess.RelayID != 0 {
				return sess.RelayID
			}
			return 1
		}())), sess.Server)
		log.Printf("CLOUD: relay inicial enviado (fallback)")
	}
	if !sentBootstrap {
		log.Printf("CLOUD: bootstrap cloud DESATIVADO na V15; sera enviado diretamente para a camera")
	}
	_ = conn.SetReadDeadline(time.Time{})
	return sess, nil
}
