package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type Mensaje struct {
	Tipo      string `json:"tipo"`
	Usuario   string `json:"usuario"`
	PassHash  string `json:"pass_hash"`
	Contenido string `json:"contenido"`
	Exito     bool   `json:"exito"`
}

type EstadoApp struct {
	mu            sync.Mutex
	conn          net.Conn
	lectorSocket  *bufio.Scanner
	autenticado   bool
	ultimoReporte string
	historialCmd  []string
	ipServer      string
	puerto        string
	periodo       string
}

var app = &EstadoApp{
	ultimoReporte: "Esperando autenticacion...",
	historialCmd:  []string{},
}

func (e *EstadoApp) enviarJSON(m Mensaje) error {
	bytes, _ := json.Marshal(m)
	_, err := e.conn.Write(append(bytes, '\n'))
	return err
}

func abrirNavegador(url string) {
	switch runtime.GOOS {
	case "windows":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "linux":
		exec.Command("xdg-open", url).Start()
	}
}

const htmlUI = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Monitor Remoto - Sistemas Operativos</title>
<style>
  body { font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }
  .container { max-width: 900px; margin: auto; }
  .card { background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
  h1 { color: #38bdf8; margin-top: 0; font-size: 1.4rem; }
  h2 { color: #94a3b8; font-size: 1rem; margin-top: 0; }
  input { padding: 10px; border-radius: 6px; border: 1px solid #334155; background: #0f172a; color: #fff; width: 220px; margin-right: 8px; }
  button { padding: 10px 16px; border-radius: 6px; border: none; background: #0284c7; color: #fff; font-weight: bold; cursor: pointer; }
  button:hover { background: #0369a1; }
  button.danger { background: #dc2626; }
  button.danger:hover { background: #b91c1c; }
  .telemetry { font-family: monospace; font-size: 1.05rem; background: #020617; color: #4ade80; padding: 14px; border-radius: 6px; border-left: 4px solid #22c55e; }
  .terminal { font-family: monospace; background: #020617; color: #f8fafc; padding: 14px; border-radius: 6px; height: 280px; overflow-y: auto; white-space: pre-wrap; font-size: 0.9rem; }
  .error { color: #f87171; margin-top: 10px; }
  .hidden { display: none; }
</style>
</head>
<body>
<div class="container">
  <div class="card" id="loginCard">
    <h1>Cliente Multiplataforma - Sistemas Operativos (Unillanos)</h1>
    <h2>Autenticacion Remota (SHA-512 + Salt)</h2>
    <input type="text" id="usuario" placeholder="Usuario (ej. ricardo)">
    <input type="password" id="password" placeholder="Password">
    <button onclick="login()">Conectar</button>
    <div id="loginMsg" class="error"></div>
  </div>

  <div id="panelCard" class="hidden">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <h1>Monitor de Recursos en Tiempo Real</h1>
        <button class="danger" onclick="enviarCmd('bye')">Cerrar Sesion (bye)</button>
      </div>
      <div class="telemetry" id="reporteBox">Cargando telemetria...</div>
    </div>

    <div class="card">
      <h2>Terminal Remota UNIX</h2>
      <div style="margin-bottom:12px;">
        <input type="text" id="cmdInput" placeholder="Comando UNIX (ej. ls -la, uname -a)" style="width:70%;" onkeydown="if(event.key==='Enter') enviarCmd()">
        <button onclick="enviarCmd()">Ejecutar</button>
      </div>
      <div class="terminal" id="terminalBox">Sesion iniciada. Escriba un comando...</div>
    </div>
  </div>
</div>

<script>
async function login() {
  const usuario = document.getElementById('usuario').value;
  const password = document.getElementById('password').value;
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({usuario, password})
  });
  const data = await res.json();
  if (data.exito) {
    document.getElementById('loginCard').classList.add('hidden');
    document.getElementById('panelCard').classList.remove('hidden');
    setInterval(actualizarEstado, 1500);
  } else {
    document.getElementById('loginMsg').innerText = data.contenido;
  }
}

async function enviarCmd(cmdForzado) {
  const input = document.getElementById('cmdInput');
  const cmd = cmdForzado || input.value;
  if (!cmd) return;
  if (!cmdForzado) input.value = '';
  await fetch('/api/cmd', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({contenido: cmd})
  });
  if (cmd === 'bye') {
    document.getElementById('terminalBox').innerText += '\n[Sesion cerrada con bye]';
  }
  setTimeout(actualizarEstado, 300);
}

async function actualizarEstado() {
  const res = await fetch('/api/estado');
  const data = await res.json();
  document.getElementById('reporteBox').innerText = data.reporte;
  const term = document.getElementById('terminalBox');
  term.innerText = data.historial.join('\n');
  term.scrollTop = term.scrollHeight;
}
</script>
</body>
</html>`

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Uso: clienteOperativosGUI <IP_SERVIDOR> <PUERTO> <PERIODO_REPORTE_SEG>")
		fmt.Println("Ej:  clienteOperativosGUI 192.168.1.11 2306 5")
		return
	}

	app.ipServer = os.Args[1]
	app.puerto = os.Args[2]
	app.periodo = os.Args[3]
	if _, err := strconv.Atoi(app.periodo); err != nil {
		fmt.Println("Error: PeriodoReporte debe ser entero.")
		return
	}

	conn, err := net.Dial("tcp4", app.ipServer+":"+app.puerto)
	if err != nil {
		fmt.Println("Error conectando al servidor:", err)
		return
	}
	defer conn.Close()

	app.conn = conn
	app.lectorSocket = bufio.NewScanner(conn)
	app.lectorSocket.Buffer(make([]byte, 64*1024), 1024*1024)

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, htmlUI)
	})

	http.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Usuario  string `json:"usuario"`
			Password string `json:"password"`
		}
		json.NewDecoder(r.Body).Decode(&creds)

		app.mu.Lock()
		defer app.mu.Unlock()

		app.enviarJSON(Mensaje{
			Tipo:     "AUTH",
			Usuario:  strings.TrimSpace(creds.Usuario),
			PassHash: strings.TrimSpace(creds.Password),
		})

		if !app.lectorSocket.Scan() {
			json.NewEncoder(w).Encode(Mensaje{Exito: false, Contenido: "Conexion cerrada por el servidor."})
			return
		}
		var resp Mensaje
		json.Unmarshal(app.lectorSocket.Bytes(), &resp)

		if resp.Exito {
			app.autenticado = true
			app.enviarJSON(Mensaje{Tipo: "CONFIG_N", Contenido: app.periodo})
			go escucharServidor()
		}
		json.NewEncoder(w).Encode(resp)
	})

	http.HandleFunc("/api/cmd", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Contenido string `json:"contenido"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		cmd := strings.TrimSpace(req.Contenido)
		app.mu.Lock()
		app.historialCmd = append(app.historialCmd, "oper% "+cmd)
		app.enviarJSON(Mensaje{Tipo: "CMD", Contenido: cmd})
		app.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})

	http.HandleFunc("/api/estado", func(w http.ResponseWriter, r *http.Request) {
		app.mu.Lock()
		defer app.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"reporte":   app.ultimoReporte,
			"historial": app.historialCmd,
		})
	})

	urlLocal := "http://127.0.0.1:8085"
	fmt.Println("Interfaz Grafica lista en:", urlLocal)
	go abrirNavegador(urlLocal)
	http.ListenAndServe("127.0.0.1:8085", nil)
}

func escucharServidor() {
	for app.lectorSocket.Scan() {
		var msg Mensaje
		if err := json.Unmarshal(app.lectorSocket.Bytes(), &msg); err != nil {
			continue
		}
		app.mu.Lock()
		switch msg.Tipo {
		case "REPORTE":
			app.ultimoReporte = msg.Contenido
		case "CMD_RES":
			app.historialCmd = append(app.historialCmd, msg.Contenido)
		}
		app.mu.Unlock()
	}
}
