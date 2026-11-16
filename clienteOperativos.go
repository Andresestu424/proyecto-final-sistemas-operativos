package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type Mensaje struct {
	Tipo      string `json:"tipo"`
	Usuario   string `json:"usuario"`
	PassHash  string `json:"pass_hash"`
	Contenido string `json:"contenido"`
	Exito     bool   `json:"exito"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Uso: clienteOperativos <IP_SERVIDOR> <PUERTO> <PERIODO_REPORTE_SEG>")
		fmt.Println("Ej:  clienteOperativos 192.168.1.11 2306 5")
		return
	}

	ipServer := os.Args[1]
	puerto := os.Args[2]
	periodoStr := os.Args[3]
	if _, err := strconv.Atoi(periodoStr); err != nil {
		fmt.Println("Error: PeriodoReporte debe ser un numero entero en segundos.")
		return
	}

	conn, err := net.Dial("tcp4", ipServer+":"+puerto)
	if err != nil {
		fmt.Println("Error conectando al servidor:", err)
		return
	}
	defer conn.Close()

	fmt.Printf("Conectado al servidor %s:%s\n", ipServer, puerto)

	lectorConsola := bufio.NewReader(os.Stdin)
	lectorSocket := bufio.NewScanner(conn)
	lectorSocket.Buffer(make([]byte, 64*1024), 1024*1024)

	enviarJSON := func(m Mensaje) {
		bytes, _ := json.Marshal(m)
		conn.Write(append(bytes, '\n'))
	}

	// Fase 1: Autenticación
	autenticado := false
	for {
		fmt.Print("Usuario: ")
		usuario, _ := lectorConsola.ReadString('\n')
		usuario = strings.TrimSpace(usuario)

		fmt.Print("Password: ")
		pass, _ := lectorConsola.ReadString('\n')
		pass = strings.TrimSpace(pass)

		hashBytes := sha256.Sum256([]byte(pass))
		passHash := fmt.Sprintf("%x", hashBytes)

		enviarJSON(Mensaje{
			Tipo:     "AUTH",
			Usuario:  usuario,
			PassHash: passHash,
		})

		if !lectorSocket.Scan() {
			fmt.Println("Conexion cerrada por el servidor (limite de intentos o IP no permitida).")
			return
		}

		var resp Mensaje
		json.Unmarshal(lectorSocket.Bytes(), &resp)
		fmt.Println(">>", resp.Contenido)
		if resp.Exito {
			autenticado = true
			break
		}
	}

	if !autenticado {
		return
	}

	// Fase 2: Enviar PeriodoReporte (n) al servidor
	enviarJSON(Mensaje{
		Tipo:      "CONFIG_N",
		Contenido: periodoStr,
	})

	fmt.Println("\n=== SESION INICIADA (Escriba 'bye' para salir) ===")

	// Goroutine 1: Recibir reportes periódicos y respuestas de comandos en paralelo
	done := make(chan struct{})
	go func() {
		defer close(done)
		for lectorSocket.Scan() {
			var msg Mensaje
			if err := json.Unmarshal(lectorSocket.Bytes(), &msg); err != nil {
				continue
			}
			switch msg.Tipo {
			case "REPORTE":
				fmt.Printf("\n[MONITOREO] %s\noper%% ", msg.Contenido)
			case "CMD_RES":
				fmt.Printf("\n--- Salida Comando ---\n%s\n----------------------\noper%% ", msg.Contenido)
			}
		}
	}()

	// Hilo principal: Enviar comandos UNIX remotamente
	for {
		fmt.Print("oper% ")
		comando, err := lectorConsola.ReadString('\n')
		if err != nil {
			break
		}
		comando = strings.TrimSpace(comando)
		if comando == "" {
			continue
		}

		enviarJSON(Mensaje{
			Tipo:      "CMD",
			Contenido: comando,
		})

		if comando == "bye" {
			fmt.Println("Cerrando conexion...")
			break
		}
	}
}
