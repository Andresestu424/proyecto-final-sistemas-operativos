package main

import (
	"bufio"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Config struct {
	IPPermitida        string
	Puerto             string
	MaxIntentos        int
	UsuariosPermitidos []string
	RutaDB             string
	RutaLog            string
}

type Mensaje struct {
	Tipo      string `json:"tipo"`
	Usuario   string `json:"usuario"`
	PassHash  string `json:"pass_hash"`
	Contenido string `json:"contenido"`
	Exito     bool   `json:"exito"`
}

var logMu sync.Mutex

func registrarLog(rutaLog, evento string) {
	logMu.Lock()
	defer logMu.Unlock()
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	linea := fmt.Sprintf("[%s] %s\n", timestamp, evento)
	fmt.Print(linea)
	f, err := os.OpenFile(rutaLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		f.WriteString(linea)
	}
}

func leerConfig(ruta string) (Config, error) {
	cfg := Config{
		RutaDB:  "/etc/oper.users.db",
		RutaLog: "/var/log/proyecto_operativos/actividad.log",
	}
	datos, err := os.ReadFile(ruta)
	if err != nil {
		return cfg, err
	}
	for _, linea := range strings.Split(string(datos), "\n") {
		linea = strings.TrimSpace(linea)
		if linea == "" || strings.HasPrefix(linea, "#") {
			continue
		}
		partes := strings.SplitN(linea, "=", 2)
		if len(partes) != 2 {
			continue
		}
		clave := strings.TrimSpace(partes[0])
		valor := strings.TrimSpace(partes[1])
		switch clave {
		case "IP_PERMITIDA":
			cfg.IPPermitida = valor
		case "PUERTO":
			cfg.Puerto = valor
		case "MAX_INTENTOS":
			cfg.MaxIntentos, _ = strconv.Atoi(valor)
		case "USUARIOS_PERMITIDOS":
			cfg.UsuariosPermitidos = strings.Split(valor, ",")
		case "RUTA_DB":
			cfg.RutaDB = valor
		case "RUTA_LOG":
			cfg.RutaLog = valor
		}
	}
	return cfg, nil
}

func validarUsuarioSHA512(usuario, passPlana string, cfg Config) (bool, string) {
	permitido := false
	for _, u := range cfg.UsuariosPermitidos {
		if strings.TrimSpace(u) == usuario {
			permitido = true
			break
		}
	}
	if !permitido {
		return false, "Usuario no autorizado en /etc/configProyecto.conf"
	}

	datos, err := os.ReadFile(cfg.RutaDB)
	if err != nil {
		return false, "Error leyendo base de datos de usuarios"
	}
	for _, linea := range strings.Split(string(datos), "\n") {
		partes := strings.SplitN(strings.TrimSpace(linea), ":", 3)
		if len(partes) == 3 && partes[0] == usuario {
			salt := partes[1]
			hashEsperado := partes[2]
			sum := sha512.Sum512([]byte(salt + passPlana))
			hashCalculado := fmt.Sprintf("%x", sum)
			if hashCalculado == hashEsperado {
				return true, "Autenticacion exitosa (SHA-512 + Salt)"
			}
			return false, "Contrasena incorrecta"
		}
	}
	return false, "Usuario no registrado en oper.users.db"
}

func obtenerMetricasSistema() string {
	loadData, _ := os.ReadFile("/proc/loadavg")
	loadFields := strings.Fields(string(loadData))
	cpuLoad := "N/A"
	if len(loadFields) > 0 {
		cpuLoad = loadFields[0]
	}

	procDirs, _ := os.ReadDir("/proc")
	numProcesos := 0
	for _, d := range procDirs {
		if d.IsDir() {
			if _, err := strconv.Atoi(d.Name()); err == nil {
				numProcesos++
			}
		}
	}

	memData, _ := os.ReadFile("/proc/meminfo")
	var memTotal, memAvail uint64
	for _, line := range strings.Split(string(memData), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			if fields[0] == "MemTotal:" {
				memTotal, _ = strconv.ParseUint(fields[1], 10, 64)
			} else if fields[0] == "MemAvailable:" {
				memAvail, _ = strconv.ParseUint(fields[1], 10, 64)
			}
		}
	}
	memUsadaMB := (memTotal - memAvail) / 1024
	memTotalMB := memTotal / 1024
	memPct := float64(memTotal-memAvail) / float64(memTotal) * 100

	var stat syscall.Statfs_t
	syscall.Statfs("/", &stat)
	discoTotalGB := float64(stat.Blocks*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	discoLibreGB := float64(stat.Bfree*uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	discoUsadoGB := discoTotalGB - discoLibreGB
	discoPct := (discoUsadoGB / discoTotalGB) * 100

	return fmt.Sprintf("[CPU Load(1m): %s | Procesos: %d | RAM: %d/%d MB (%.1f%%) | Disco: %.1f/%.1f GB (%.1f%%)]",
		cpuLoad, numProcesos, memUsadaMB, memTotalMB, memPct, discoUsadoGB, discoTotalGB, discoPct)
}

func main() {
	rutaConf := "/etc/configProyecto.conf"
	cfg, err := leerConfig(rutaConf)
	if err != nil {
		fmt.Println("Error cargando /etc/configProyecto.conf:", err)
		return
	}

	listener, err := net.Listen("tcp4", "0.0.0.0:"+cfg.Puerto)
	if err != nil {
		fmt.Println("Error abriendo puerto:", err)
		return
	}
	defer listener.Close()

	registrarLog(cfg.RutaLog, fmt.Sprintf("SERVIDOR INICIADO en puerto :%s (IP permitida: %s)", cfg.Puerto, cfg.IPPermitida))

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go manejarCliente(conn, cfg)
	}
}

func manejarCliente(conn net.Conn, cfg Config) {
	defer conn.Close()
	ipCliente, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	registrarLog(cfg.RutaLog, fmt.Sprintf("CONEXION ENTRANTE desde IP %s", ipCliente))

	if cfg.IPPermitida != "*" && ipCliente != cfg.IPPermitida {
		registrarLog(cfg.RutaLog, fmt.Sprintf("BLOQUEO IP no autorizada: %s", ipCliente))
		return
	}

	lector := bufio.NewScanner(conn)
	var writeMu sync.Mutex
	enviarJSON := func(m Mensaje) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		bytes, _ := json.Marshal(m)
		_, err := conn.Write(append(bytes, '\n'))
		return err
	}

	autenticado := false
	usuarioActivo := ""
	for intento := 1; intento <= cfg.MaxIntentos; intento++ {
		if !lector.Scan() {
			return
		}
		var req Mensaje
		if err := json.Unmarshal(lector.Bytes(), &req); err != nil || req.Tipo != "AUTH" {
			return
		}

		ok, detalle := validarUsuarioSHA512(req.Usuario, req.PassHash, cfg)
		if ok {
			usuarioActivo = req.Usuario
			registrarLog(cfg.RutaLog, fmt.Sprintf("LOGIN EXITOSO usuario='%s' desde IP %s", usuarioActivo, ipCliente))
			enviarJSON(Mensaje{Tipo: "AUTH_RES", Exito: true, Contenido: detalle})
			autenticado = true
			break
		}

		msgError := fmt.Sprintf("%s (Intento %d/%d)", detalle, intento, cfg.MaxIntentos)
		registrarLog(cfg.RutaLog, fmt.Sprintf("LOGIN FALLIDO usuario='%s' desde IP %s -> %s", req.Usuario, ipCliente, msgError))
		enviarJSON(Mensaje{Tipo: "AUTH_RES", Exito: false, Contenido: msgError})
	}

	if !autenticado {
		registrarLog(cfg.RutaLog, fmt.Sprintf("DESCONEXION por exceso de intentos fallidos IP %s", ipCliente))
		return
	}

	if !lector.Scan() {
		return
	}
	var cfgMsg Mensaje
	json.Unmarshal(lector.Bytes(), &cfgMsg)
	periodoSeg, err := strconv.Atoi(cfgMsg.Contenido)
	if err != nil || periodoSeg <= 0 {
		periodoSeg = 5
	}
	registrarLog(cfg.RutaLog, fmt.Sprintf("MONITOREO CONFIGURADO cada %d s para usuario='%s'", periodoSeg, usuarioActivo))

	salir := make(chan struct{})

	go func() {
		ticker := time.NewTicker(time.Duration(periodoSeg) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-salir:
				return
			case <-ticker.C:
				reporte := obtenerMetricasSistema()
				if err := enviarJSON(Mensaje{Tipo: "REPORTE", Contenido: reporte}); err != nil {
					return
				}
			}
		}
	}()

	for lector.Scan() {
		var cmdMsg Mensaje
		if err := json.Unmarshal(lector.Bytes(), &cmdMsg); err != nil {
			continue
		}
		if cmdMsg.Tipo == "CMD" {
			comando := strings.TrimSpace(cmdMsg.Contenido)
			registrarLog(cfg.RutaLog, fmt.Sprintf("CMD usuario='%s' (%s): %s", usuarioActivo, ipCliente, comando))

			if comando == "bye" {
				registrarLog(cfg.RutaLog, fmt.Sprintf("SESION CERRADA ('bye') por usuario='%s'", usuarioActivo))
				close(salir)
				return
			}

			out, err := exec.Command("bash", "-c", comando).CombinedOutput()
			respuesta := string(out)
			if err != nil && respuesta == "" {
				respuesta = err.Error()
			}
			if respuesta == "" {
				respuesta = "(Comando ejecutado sin salida)"
			}
			enviarJSON(Mensaje{Tipo: "CMD_RES", Contenido: respuesta})
		}
	}
	close(salir)
}
