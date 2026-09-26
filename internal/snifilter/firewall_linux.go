//go:build linux

package snifilter

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/florianl/go-nfqueue/v2"
	"golang.org/x/sys/unix"
)

const (
	// chainName is the name of the netfilter chain managed by the SNI filter.
	chainName = "AGH_SNI"

	// outputChain is the name of the netfilter chain that the filter's chain
	// is called from.
	outputChain = "OUTPUT"

	// filterTable is the name of the netfilter table the filter works in.
	filterTable = "filter"

	// connBytesLimit is the number of bytes at the beginning of every
	// connection that are sent to the userspace.  A ClientHello is limited by
	// a single TLS record, so this is enough to read the server name even
	// when it spans several TCP segments, and to catch the retransmissions of
	// them.
	connBytesLimit = 20000

	// maxQueueLen is the maximum number of packets waiting for the verdict.
	// The rest of the packets are passed through by the kernel, see the
	// queue-bypass option of the rule.
	maxQueueLen = 1024

	// queueReadTimeout is the time the queue waits for the packets.
	queueReadTimeout = 100 * time.Millisecond

	// queueWriteTimeout is the time the queue waits to hand the packet over
	// to the kernel.
	queueWriteTimeout = 20 * time.Millisecond

	// rulesCheckInterval is the interval at which the filter checks that its
	// netfilter rules are still installed.  Some of the network managers and
	// Android modules flush the rules when the network changes.
	rulesCheckInterval = 30 * time.Second

	// shutdownTimeout is the time given to the commands that remove the
	// rules on shutdown.
	shutdownTimeout = 10 * time.Second
)

// platform is the Linux-specific state of the SNI filter.
type platform struct {
	// nf is the connection to the netfilter queue subsystem.
	nf *nfqueue.Nfqueue

	// iptables is the resolved path to the command that manages the IPv4
	// rules.  It's empty if the rules are not installed.
	iptables string

	// ip6tables is the resolved path to the command that manages the IPv6
	// rules.  It's empty if the rules are not installed.
	ip6tables string

	// rulesMu protects the rules and the paths to the commands that manage
	// them.
	rulesMu sync.Mutex

	// raw4 is the raw socket used to inject the IPv4 reset segments.  It's
	// negative if the socket is not available.
	raw4 int

	// raw6 is the raw socket used to inject the IPv6 reset segments.  It's
	// negative if the socket is not available.
	raw6 int
}

// startFirewall installs the netfilter rules and starts inspecting the
// connections.  ctx must be canceled when the filter is shut down.
func (f *Filter) startFirewall(ctx context.Context) (err error) {
	f.openRawSockets()

	err = f.openQueue(ctx)
	if err != nil {
		f.closeRawSockets()

		return fmt.Errorf("opening the queue: %w", err)
	}

	if !f.manageRules {
		// The rules are installed and removed by the operator, for example by
		// the script of a Magisk module.
		f.logger.InfoContext(
			ctx,
			"netfilter rules aren't managed by adguard home; make sure "+
				"they send the packets to the queue",
			"chain", chainName,
			"queue_num", f.queueNum,
		)

		return nil
	}

	err = f.setupRules(ctx)
	if err != nil {
		f.closeQueue()
		f.closeRawSockets()

		return fmt.Errorf("installing the netfilter rules: %w", err)
	}

	f.wg.Add(1)
	go f.watchRules(ctx)

	f.checkReversePathFilter(ctx)

	return nil
}

// stopFirewall removes the netfilter rules and stops inspecting the
// connections.
func (f *Filter) stopFirewall(ctx context.Context) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if f.manageRules {
		f.removeRules(ctx)
	}

	f.closeQueue()
	f.closeRawSockets()
}

// setupRules installs the rules that send the beginnings of the outgoing TLS
// connections to the queue.  It requires the root rights.
func (f *Filter) setupRules(ctx context.Context) (err error) {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()

	f.iptables, err = exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("looking up iptables: %w", err)
	}

	err = f.setupChainRules(ctx, f.iptables)
	if err != nil {
		return fmt.Errorf("installing the ipv4 rules: %w", err)
	}

	// Devices that don't use IPv6 may not have the command at all, so the
	// lack of it is not an error.
	f.ip6tables, err = exec.LookPath("ip6tables")
	if err != nil {
		f.ip6tables = ""
		f.logger.WarnContext(
			ctx,
			"ip6tables is not available; ipv6 connections are not inspected",
			slogutil.KeyError,
			err,
		)

		return nil
	}

	err = f.setupChainRules(ctx, f.ip6tables)
	if err != nil {
		f.ip6tables = ""
		f.logger.WarnContext(
			ctx,
			"installing the ipv6 rules",
			slogutil.KeyError,
			err,
		)
	}

	return nil
}

// setupChainRules installs the rules of the filter for one protocol family.
// cmd must be the path to the command that manages the rules of that family.
// f.rulesMu must be locked.
func (f *Filter) setupChainRules(ctx context.Context, cmd string) (err error) {
	// Create the chain if it's not there, the error means it exists.
	_ = f.runCmd(ctx, cmd, "-N", chainName)

	err = f.runCmd(ctx, cmd, "-F", chainName)
	if err != nil {
		return err
	}

	for _, args := range f.chainRuleArgs() {
		err = f.runCmd(ctx, cmd, args...)
		if err != nil {
			return err
		}
	}

	// Make sure that the chain is called from the output chain.
	err = f.runCmd(ctx, cmd, "-C", outputChain, "-j", chainName)
	if err == nil {
		return nil
	}

	return f.runCmd(ctx, cmd, "-I", outputChain, "1", "-j", chainName)
}

// chainRuleArgs returns the argument lists of the rules of the filter's chain.
func (f *Filter) chainRuleArgs() (rules [][]string) {
	// The loopback traffic isn't a part of the network activity that needs to
	// be filtered, and blocking it may break the local services.
	rules = append(rules, []string{"-A", chainName, "-o", "lo", "-j", "RETURN"})

	if f.dropQUIC {
		args := []string{
			"-A", chainName,
			"-p", "udp",
			"-m", "multiport", "--dports", f.portsArg(),
		}
		args = append(args, f.ownerArgs()...)
		args = append(args, "-j", "REJECT")

		rules = append(rules, args)
	}

	args := []string{
		"-A", chainName,
		"-p", "tcp",
		"-m", "multiport", "--dports", f.portsArg(),
	}
	args = append(args, f.ownerArgs()...)
	args = append(
		args,
		"-m", "connbytes",
		"--connbytes", "0:"+strconv.Itoa(connBytesLimit),
		"--connbytes-dir", "original",
		"--connbytes-mode", "bytes",
		"-j", "NFQUEUE",
		"--queue-num", strconv.FormatUint(uint64(f.queueNum), 10),
		"--queue-bypass",
	)

	return append(rules, args)
}

// portsArg returns the argument of the multiport match with the inspected
// ports.
func (f *Filter) portsArg() (ports string) {
	nums := make([]string, len(f.ports))
	for i, p := range f.ports {
		nums[i] = strconv.FormatUint(uint64(p), 10)
	}

	return strings.Join(nums, ",")
}

// ownerArgs returns the arguments of the match that limits the inspected
// packets to the processes of the configured users.
func (f *Filter) ownerArgs() (args []string) {
	if len(f.uids) == 0 {
		return nil
	}

	args = []string{"-m", "owner"}
	for _, uids := range f.uids {
		args = append(args, "--uid-owner", uids)
	}

	return args
}

// removeRules removes the netfilter rules of the filter.
func (f *Filter) removeRules(ctx context.Context) {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()

	for _, cmd := range []string{f.iptables, f.ip6tables} {
		if cmd == "" {
			continue
		}

		// Ignore the errors, since the rules could be already removed by a
		// network manager or a module.
		_ = f.runCmd(ctx, cmd, "-D", outputChain, "-j", chainName)
		_ = f.runCmd(ctx, cmd, "-F", chainName)
		_ = f.runCmd(ctx, cmd, "-X", chainName)
	}

	f.iptables, f.ip6tables = "", ""
}

// runCmd runs the netfilter command and returns an error with its output.
func (f *Filter) runCmd(ctx context.Context, cmd string, args ...string) (err error) {
	args = append([]string{"-w", "2", "-t", filterTable}, args...)
	out, err := exec.CommandContext(ctx, cmd, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"%s %s: %w: %s",
			cmd,
			strings.Join(args, " "),
			err,
			bytes.TrimSpace(out),
		)
	}

	return nil
}

// watchRules checks that the rules are still installed and restores them if
// they are gone.
func (f *Filter) watchRules(ctx context.Context) {
	defer f.wg.Done()

	ticker := time.NewTicker(rulesCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			f.checkRules(ctx)
			f.expireFlows()
		}
	}
}

// checkRules restores the rules of the filter if they are gone.
func (f *Filter) checkRules(ctx context.Context) {
	f.rulesMu.Lock()
	defer f.rulesMu.Unlock()

	for _, cmd := range []string{f.iptables, f.ip6tables} {
		if cmd == "" {
			continue
		}

		err := f.runCmd(ctx, cmd, "-C", outputChain, "-j", chainName)
		if err == nil {
			continue
		}

		f.logger.InfoContext(ctx, "restoring the netfilter rules", "cmd", cmd)

		err = f.setupChainRules(ctx, cmd)
		if err != nil {
			f.logger.ErrorContext(ctx, "restoring the netfilter rules", slogutil.KeyError, err)
		}
	}
}

// checkReversePathFilter warns if the kernel is likely to drop the injected
// reset segments, since the blocked connections would then hang instead of
// failing fast.  See the rp_filter description in
// https://docs.kernel.org/networking/ip-sysctl.html.
func (f *Filter) checkReversePathFilter(ctx context.Context) {
	// The effective mode is the strictest of the per-interface and the "all"
	// values.
	for _, name := range []string{"all", "lo"} {
		path := "/proc/sys/net/ipv4/conf/" + name + "/rp_filter"

		data, err := os.ReadFile(path)
		if err != nil {
			f.logger.DebugContext(ctx, "reading rp_filter", "path", path, slogutil.KeyError, err)

			continue
		}

		if strings.TrimSpace(string(data)) != "1" {
			continue
		}

		f.logger.WarnContext(
			ctx,
			"ipv4 reverse path filtering is strict, so the resets for the "+
				"blocked connections may not reach the clients and those "+
				"connections will hang instead of failing fast",
			"path",
			path,
		)
	}
}

// openQueue opens the netfilter queue and starts processing the packets.  ctx
// must be canceled to stop the processing.
func (f *Filter) openQueue(ctx context.Context) (err error) {
	conf := &nfqueue.Config{
		NfQueue:      f.queueNum,
		MaxPacketLen: 0xffff,
		MaxQueueLen:  maxQueueLen,
		Copymode:     nfqueue.NfQnlCopyPacket,
		// The family of the queue is not used by the kernel to route the
		// packets anymore, so the packets of both IPv4 and IPv6 arrive into
		// the same queue.
		AfFamily:     unix.AF_UNSPEC,
		ReadTimeout:  queueReadTimeout,
		WriteTimeout: queueWriteTimeout,
	}

	f.nf, err = nfqueue.Open(conf)
	if err != nil {
		return err
	}

	err = f.nf.Register(ctx, f.handlePacket)
	if err != nil {
		f.closeQueue()

		return err
	}

	return nil
}

// closeQueue closes the netfilter queue.
func (f *Filter) closeQueue() {
	if f.nf == nil {
		return
	}

	err := f.nf.Close()
	if err != nil {
		f.logger.Debug("closing the queue", slogutil.KeyError, err)
	}

	f.nf = nil
}

// handlePacket processes a packet received from the kernel and reports the
// verdict for it.
func (f *Filter) handlePacket(a nfqueue.Attribute) (ret int) {
	if a.PacketID == nil || a.Payload == nil {
		return 0
	}

	verdict := nfqueue.NfAccept

	p, err := parsePacket(*a.Payload)
	if err == nil {
		res := f.inspect(p)
		switch res.verdict {
		case verdictDrop:
			verdict = nfqueue.NfDrop
		case verdictReset:
			f.sendReset(&res.toClient)
			f.sendReset(&res.toServer)

			verdict = nfqueue.NfDrop
		default:
			// Pass the packet through.
		}
	}

	err = f.nf.SetVerdict(*a.PacketID, verdict)
	if err != nil {
		f.logger.Debug("setting the verdict", "id", *a.PacketID, slogutil.KeyError, err)
	}

	return 0
}

// openRawSockets opens the sockets used to inject the reset segments.  The
// errors are logged, since the filter can still block the connections by
// dropping the packets.
func (f *Filter) openRawSockets() {
	f.raw4, f.raw6 = -1, -1

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		f.logger.Warn(
			"opening the ipv4 raw socket; blocked connections will hang instead of being reset",
			slogutil.KeyError,
			err,
		)
	} else {
		f.raw4 = sock
	}

	sock, err = unix.Socket(unix.AF_INET6, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_RAW)
	if err != nil {
		f.logger.Warn(
			"opening the ipv6 raw socket; blocked connections will hang instead of being reset",
			slogutil.KeyError,
			err,
		)
	} else {
		f.raw6 = sock
	}
}

// closeRawSockets closes the sockets used to inject the reset segments.
func (f *Filter) closeRawSockets() {
	for _, sock := range []*int{&f.raw4, &f.raw6} {
		if *sock < 0 {
			continue
		}

		err := unix.Close(*sock)
		if err != nil {
			f.logger.Debug("closing the raw socket", slogutil.KeyError, err)
		}

		*sock = -1
	}
}

// sendReset injects the reset segment into the network stack.  The errors are
// only logged, since the packet processing must not be interrupted by them.
func (f *Filter) sendReset(seg *rstSegment) {
	addr := seg.dst.Addr()

	// A zoned address requires the interface to be resolved, which the raw
	// sockets don't do.
	if addr.Zone() != "" {
		f.logger.Debug("not sending a reset to a zoned address", "dst", seg.dst.String())

		return
	}

	var err error
	switch {
	case addr.Is4():
		if f.raw4 < 0 {
			f.logger.Debug("not sending a reset: no ipv4 raw socket")

			return
		}

		err = unix.Sendto(f.raw4, buildReset4(seg), 0, &unix.SockaddrInet4{Addr: addr.As4()})
	case addr.Is6():
		if f.raw6 < 0 {
			f.logger.Debug("not sending a reset: no ipv6 raw socket")

			return
		}

		err = unix.Sendto(f.raw6, buildReset6(seg), 0, &unix.SockaddrInet6{Addr: addr.As16()})
	default:
		// Can't happen, since an address is either IPv4 or IPv6.
		return
	}

	if err != nil {
		f.logger.Debug("sending the reset segment", "dst", seg.dst.String(), slogutil.KeyError, err)
	}
}

// buildReset4 returns an IPv4 packet with a TCP reset segment.
func buildReset4(seg *rstSegment) (pkt []byte) {
	src := seg.src.Addr().As4()
	dst := seg.dst.Addr().As4()

	pkt = make([]byte, 0, ipv4HeaderLen+tcpHeaderLen)
	pkt = appendIPv4Header(pkt, src[:], dst[:], tcpHeaderLen)

	return appendTCPHeader(pkt, seg, src[:], dst[:], false)
}

// buildReset6 returns an IPv6 packet with a TCP reset segment.
func buildReset6(seg *rstSegment) (pkt []byte) {
	src := seg.src.Addr().As16()
	dst := seg.dst.Addr().As16()

	pkt = make([]byte, 0, ipv6HeaderLen+tcpHeaderLen)
	pkt = appendIPv6Header(pkt, src[:], dst[:], tcpHeaderLen)

	return appendTCPHeader(pkt, seg, src[:], dst[:], true)
}

// appendIPv4Header appends an IPv4 header of a TCP segment of payloadLen
// bytes to b and returns the result.
func appendIPv4Header(b, src, dst []byte, payloadLen int) []byte {
	// Version, IHL, DSCP, and ECN.
	b = append(b, 0x45, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(ipv4HeaderLen+payloadLen))
	// Identification.
	b = binary.BigEndian.AppendUint16(b, 0)
	// The don't-fragment flag.
	b = binary.BigEndian.AppendUint16(b, 0x4000)
	// TTL and the protocol.
	b = append(b, 64, unix.IPPROTO_TCP)
	// The header checksum, which is filled in below.
	b = binary.BigEndian.AppendUint16(b, 0)
	b = append(b, src...)
	b = append(b, dst...)

	header := b[len(b)-ipv4HeaderLen:]
	cs := newChecksummer()
	cs.add(header)
	binary.BigEndian.PutUint16(header[10:12], cs.value())

	return b
}

// appendIPv6Header appends an IPv6 header of a TCP segment of payloadLen bytes
// to b and returns the result.
func appendIPv6Header(b, src, dst []byte, payloadLen int) []byte {
	// Version, traffic class, and flow label.
	b = append(b, 0x60, 0, 0, 0)
	// The payload length.
	b = binary.BigEndian.AppendUint16(b, uint16(payloadLen))
	// The next header and the hop limit.
	b = append(b, unix.IPPROTO_TCP, 64)
	b = append(b, src...)
	b = append(b, dst...)

	return b
}

// appendTCPHeader appends a TCP header with the reset flag to b and returns
// the result with the checksum filled in.
func appendTCPHeader(b []byte, seg *rstSegment, src, dst []byte, ipv6 bool) []byte {
	b = binary.BigEndian.AppendUint16(b, seg.src.Port())
	b = binary.BigEndian.AppendUint16(b, seg.dst.Port())
	b = binary.BigEndian.AppendUint32(b, seg.seq)
	b = binary.BigEndian.AppendUint32(b, seg.ack)
	// The data offset and the flags.
	b = append(b, tcpHeaderLen/4<<4, tcpFlagRST|tcpFlagACK)
	// The window, the checksum, and the urgent pointer.
	b = append(b, 0, 0, 0, 0, 0, 0)

	header := b[len(b)-tcpHeaderLen:]
	cs := newChecksummer()
	cs.add(src)
	cs.add(dst)
	if ipv6 {
		// The upper-layer packet length, see RFC 8200.
		cs.add([]byte{0, 0, 0, uint8(tcpHeaderLen)})
		cs.add([]byte{0, 0, 0, unix.IPPROTO_TCP})
	} else {
		// The zero field and the protocol, see RFC 793.
		cs.add([]byte{0, unix.IPPROTO_TCP})
		cs.add([]byte{0, uint8(tcpHeaderLen)})
	}
	cs.add(header)

	binary.BigEndian.PutUint16(header[16:18], cs.value())

	return b
}

// checksummer accumulates the one's complement sum of bytes.
type checksummer struct {
	sum uint32
}

// newChecksummer returns a new checksummer.
func newChecksummer() (cs *checksummer) {
	return &checksummer{}
}

// add adds the bytes of b to the sum.
func (cs *checksummer) add(b []byte) {
	for len(b) >= 2 {
		cs.sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}

	if len(b) > 0 {
		cs.sum += uint32(b[0]) << 8
	}
}

// value returns the one's complement checksum.
func (cs *checksummer) value() (sum uint16) {
	for cs.sum > 0xffff {
		cs.sum = (cs.sum & 0xffff) + (cs.sum >> 16)
	}

	return ^uint16(cs.sum)
}
