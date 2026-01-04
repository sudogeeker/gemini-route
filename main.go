package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Version and metadata
const AppName = "Gemini-IPv6-Proxy"

// Log levels
const (
	LevelDebug = iota
	LevelInfo
	LevelWarn
	LevelError
)

// Global state
var (
	config       Config
	logger       *LeveledLogger
	localSubnets []*net.IPNet
	validIPv6s   []string
	mu           sync.RWMutex // Protects validIPv6s
	keyRegex     = regexp.MustCompile(`(?i)(key|api_key)=([^&]+)`)
)

// Config holds application settings
type Config struct {
	TargetHost     string
	ListenAddr     string
	IPv6ListURL    string
	UpdateInterval time.Duration
	ManualCIDRs    []string
	LogLevel       string
	LogFile        string
}

// LeveledLogger provides basic leveled logging
type LeveledLogger struct {
	level  int
	logger *log.Logger
}

func main() {
	parseConfig()
	setupLogger()

	// 1. Network Initialization
	if err := initLocalSubnet(); err != nil {
		logger.Fatalf("Failed to init local subnet: %v", err)
	}

	// 2. Initial IP List Fetch
	if err := fetchAndReloadIPs(); err != nil {
		logger.Warnf("Initial IP fetch failed: %v", err)
	}
	go ipUpdaterLoop()

	// 3. Reverse Proxy Setup
	targetURL := &url.URL{Scheme: "https", Host: config.TargetHost}

	proxy := &httputil.ReverseProxy{
		Transport:     newTransport(),
		FlushInterval: -1, // Disable buffering for streaming support
		Director: func(req *http.Request) {
			req.URL.Scheme = targetURL.Scheme
			req.URL.Host = targetURL.Host
			req.Host = targetURL.Host
			req.Header.Del("X-Forwarded-For")
			if _, ok := req.Header["User-Agent"]; !ok {
				req.Header.Set("User-Agent", "")
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if r.Context().Err() == nil {
				logger.Errorf("Proxy error: %v", err)
			}
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	// 4. Start Server
	server := &http.Server{
		Addr:    config.ListenAddr,
		Handler: logMiddleware(proxy),
	}

	fmt.Printf("%s started on %s (Level: %s)\n", AppName, config.ListenAddr, config.LogLevel)
	if err := server.ListenAndServe(); err != nil {
		logger.Fatalf("Server failed: %v", err)
	}
}

// newTransport creates a high-performance transport with IPv6 rotation
func newTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          2000,
		MaxIdleConnsPerHost:   1000,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: config.TargetHost,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Only intercept traffic to the target host
			if strings.Contains(addr, config.TargetHost) {
				return dialCustom(ctx)
			}
			// Fallback for other hosts
			d := net.Dialer{Timeout: 30 * time.Second}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// dialCustom handles the core IPv6 rotation logic (Src & Dest)
func dialCustom(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	// Bind random source IPv6
	if sn := pickRandomLocalSubnet(); sn != nil {
		if srcIP := genRandomIPv6(sn); srcIP != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: srcIP}
		}
	}

	// Pick random destination IPv6
	destIP := pickRandomDestIP()
	if destIP == "" {
		// Fallback to DNS resolution if list is empty
		return dialer.DialContext(ctx, "tcp6", net.JoinHostPort(config.TargetHost, "443"))
	}

	if logger.level <= LevelDebug {
		src := "System"
		if dialer.LocalAddr != nil {
			src = dialer.LocalAddr.String()
		}
		logger.Debugf("Dial: %s -> %s", src, destIP)
	}

	// Force IPv6 connection via IP to bypass DNS
	conn, err := dialer.DialContext(ctx, "tcp6", net.JoinHostPort(destIP, "443"))
	if err != nil {
		logger.Warnf("Dial failed to %s: %v", destIP, err)
		return nil, err
	}
	return conn, nil
}

// ipUpdaterLoop runs in background to refresh valid IPs
func ipUpdaterLoop() {
	ticker := time.NewTicker(config.UpdateInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := fetchAndReloadIPs(); err != nil {
			logger.Warnf("IP update failed: %v", err)
		} else {
			logger.Debugf("IP list updated")
		}
	}
}

func fetchAndReloadIPs() error {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(config.IPv6ListURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("http status: %d", resp.StatusCode)
	}

	var tempIPs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Validate IPv6
		if ip := net.ParseIP(line); ip != nil && ip.To4() == nil {
			tempIPs = append(tempIPs, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read error: %v", err)
	}
	if len(tempIPs) == 0 {
		return fmt.Errorf("empty valid IP list")
	}

	mu.Lock()
	validIPv6s = tempIPs
	count := len(validIPv6s)
	mu.Unlock()

	logger.Infof("Loaded %d IPv6 addresses", count)
	return nil
}

// genRandomIPv6 generates a random IP within the subnet: (Prefix & Mask) | (Random & ^Mask)
func genRandomIPv6(network *net.IPNet) net.IP {
	if network == nil {
		return nil
	}
	netIP := network.IP.To16()
	mask := network.Mask
	if netIP == nil || len(mask) != 16 {
		return nil
	}

	randBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, randBytes); err != nil {
		return nil
	}

	finalIP := make(net.IP, 16)
	for i := 0; i < 16; i++ {
		finalIP[i] = (netIP[i] & mask[i]) | (randBytes[i] & ^mask[i])
	}
	return finalIP
}

func pickRandomLocalSubnet() *net.IPNet {
	if len(localSubnets) == 0 {
		return nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(localSubnets))))
	if err != nil {
		return localSubnets[0]
	}
	return localSubnets[n.Int64()]
}

func pickRandomDestIP() string {
	mu.RLock()
	defer mu.RUnlock()
	if len(validIPv6s) == 0 {
		return ""
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(validIPv6s))))
	if err != nil {
		return validIPv6s[0]
	}
	return validIPv6s[n.Int64()]
}

func initLocalSubnet() error {
	// If any CIDR is provided externally, do NOT auto-detect. We trust the provided list.
	if len(config.ManualCIDRs) > 0 {
		subnets, err := parseIPv6CIDRs(config.ManualCIDRs)
		if err != nil {
			return err
		}
		localSubnets = subnets
		logger.Infof("Using %d manual subnet(s)", len(localSubnets))
		return nil
	}

	// Auto-detect if not provided
	if n, err := detectLocalIPv6Subnet(); err == nil && n != nil {
		localSubnets = []*net.IPNet{n}
		logger.Infof("Auto-detected subnet: %s", n.String())
		return nil
	}

	return fmt.Errorf("no subnet detected, use -cidr or IPV6_CIDR")
}

func parseIPv6CIDRs(cidrs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, raw := range cidrs {
		for _, token := range splitCIDRInput(raw) {
			_, n, err := net.ParseCIDR(token)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %v", token, err)
			}
			if n == nil || n.IP == nil {
				return nil, fmt.Errorf("invalid CIDR %q", token)
			}
			ip := n.IP.To16()
			if ip == nil || ip.To4() != nil {
				return nil, fmt.Errorf("CIDR must be IPv6: %q", token)
			}
			if len(n.Mask) != 16 {
				return nil, fmt.Errorf("CIDR mask must be IPv6: %q", token)
			}
			// Normalize IP to masked network address
			n.IP = ip.Mask(n.Mask)
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty CIDR list")
	}
	return out, nil
}

func splitCIDRInput(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	}) {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// detectLocalIPv6Subnet tries to infer a usable IPv6 subnet from local interfaces,
// without calling external commands. It prefers global unicast addresses with a
// prefix length < 128 and skips link-local (fe80::/10) and other non-routable ranges.
func detectLocalIPv6Subnet() (*net.IPNet, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	type cand struct {
		net   *net.IPNet
		score int
	}
	var best *cand

	for _, ifc := range ifaces {
		// Skip down or loopback interfaces
		if (ifc.Flags&net.FlagUp) == 0 || (ifc.Flags&net.FlagLoopback) != 0 {
			continue
		}

		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet == nil || ipnet.IP == nil {
				continue
			}
			ip := ipnet.IP.To16()
			if ip == nil || ip.To4() != nil {
				continue
			}
			// Skip link-local and multicast
			if ip.IsLinkLocalUnicast() || ip.IsMulticast() {
				continue
			}
			// Skip unique local (fc00::/7) to avoid selecting private-only ranges by default
			if len(ip) == 16 && (ip[0]&0xfe) == 0xfc {
				continue
			}
			if !ip.IsGlobalUnicast() {
				continue
			}

			ones, bits := ipnet.Mask.Size()
			if bits != 128 || ones >= 128 {
				continue
			}

			networkIP := ip.Mask(ipnet.Mask)
			n := &net.IPNet{IP: networkIP, Mask: ipnet.Mask}

			// Heuristic scoring:
			// Prefer prefix <= 64 (common routed subnets) and bigger subnets (smaller ones value)
			score := 0
			if ones <= 64 {
				score += 1000
			}
			// Slightly prefer typical /64 over very small ranges like /120
			score += (128 - ones)

			if best == nil || score > best.score {
				best = &cand{net: n, score: score}
			}
		}
	}

	if best == nil || best.net == nil {
		return nil, fmt.Errorf("no suitable IPv6 subnet found")
	}
	return best.net, nil
}

// logMiddleware logs requests and redacts sensitive keys
func logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if logger.level > LevelInfo {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := &responseWrapper{ResponseWriter: w, statusCode: 200}
		next.ServeHTTP(ww, r)

		safeURL := keyRegex.ReplaceAllString(r.URL.String(), "$1=[REDACTED]")
		logger.Infof("[%d] %s %s | %s | %v", ww.statusCode, r.Method, safeURL, r.RemoteAddr, time.Since(start))
	})
}

// Helper: Config Parsing
func parseConfig() {
	// Defaults
	config = Config{
		TargetHost:     "generativelanguage.googleapis.com",
		ListenAddr:     ":8080",
		IPv6ListURL:    "https://raw.githubusercontent.com/ccbkkb/ipv6-googleapis/refs/heads/main/valid_ips.txt",
		UpdateInterval: 1 * time.Hour,
		LogLevel:       "ERROR",
	}

	// Environment overrides
	if v := os.Getenv("TARGET_HOST"); v != "" {
		config.TargetHost = v
	}
	if v := os.Getenv("LISTEN_ADDR"); v != "" {
		config.ListenAddr = v
	}
	if v := os.Getenv("IPV6_CIDR"); v != "" {
		config.ManualCIDRs = splitCIDRInput(v)
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" {
		config.LogLevel = v
	}
	if v := os.Getenv("LOG_FILE"); v != "" {
		config.LogFile = v
	}

	// Flags overrides
	var flagCIDRs []string
	flag.StringVar(&config.ListenAddr, "listen", config.ListenAddr, "Address to listen on")
	flag.Func("cidr", "Manual IPv6 CIDR(s). Repeatable or comma-separated (e.g. 2001:db8::/48,2001:db8:abcd::/64)", func(v string) error {
		flagCIDRs = append(flagCIDRs, splitCIDRInput(v)...)
		return nil
	})
	flag.StringVar(&config.LogLevel, "log-level", config.LogLevel, "Log level: DEBUG, INFO, WARN, ERROR")
	flag.StringVar(&config.LogFile, "log-file", config.LogFile, "Path to log file")
	flag.Parse()

	if len(flagCIDRs) > 0 {
		config.ManualCIDRs = flagCIDRs
	}
}

// Helper: Logger Setup
func setupLogger() {
	lvl := LevelError
	switch strings.ToUpper(config.LogLevel) {
	case "DEBUG":
		lvl = LevelDebug
	case "INFO":
		lvl = LevelInfo
	case "WARN":
		lvl = LevelWarn
	}

	var w io.Writer = os.Stdout
	if config.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(config.LogFile), 0755); err == nil {
			if f, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
				w = io.MultiWriter(os.Stdout, f)
			}
		}
	}

	logger = &LeveledLogger{
		level:  lvl,
		logger: log.New(w, "", log.LstdFlags|log.Lmicroseconds),
	}
}

// Helper: Logging Methods
func (l *LeveledLogger) Debugf(f string, v ...interface{}) {
	if l.level <= LevelDebug {
		l.logger.Printf("[DEBG] "+f, v...)
	}
}
func (l *LeveledLogger) Infof(f string, v ...interface{}) {
	if l.level <= LevelInfo {
		l.logger.Printf("[INFO] "+f, v...)
	}
}
func (l *LeveledLogger) Warnf(f string, v ...interface{}) {
	if l.level <= LevelWarn {
		l.logger.Printf("[WARN] "+f, v...)
	}
}
func (l *LeveledLogger) Errorf(f string, v ...interface{}) {
	if l.level <= LevelError {
		l.logger.Printf("[ERRO] "+f, v...)
	}
}
func (l *LeveledLogger) Fatalf(f string, v ...interface{}) {
	l.logger.Printf("[FATL] "+f, v...)
	os.Exit(1)
}

// Helper: Response Wrapper
type responseWrapper struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWrapper) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
func (rw *responseWrapper) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
