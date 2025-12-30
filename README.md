# Scanner de Portas em Python (TCP & UDP)

Este projeto é um **Scanner de Portas** escrito em Python utilizando **Scapy** e **Programação Orientada a Objetos (OO)**.

---

## Fundamentos dos Protocolos (Teoria)

### TCP (Transmission Control Protocol)

TCP é um protocolo **orientado à conexão** que utiliza o **handshake de três vias**:

1. **SYN** → solicitação para iniciar uma conexão
2. **SYN-ACK** → o servidor aceita
3. **ACK** → conexão estabelecida

O TCP possui **flags** que indicam o estado da conexão:

* `S` → SYN
* `A` → ACK
* `R` → RST (Reset)
* `F` → FIN (Encerrar conexão)

Como o TCP é *stateful*, o **port scanning se baseia em como os servidores respondem a handshakes inválidos ou incompletos**.

---

### UDP (User Datagram Protocol)

UDP é um protocolo **sem conexão**:

* Não possui handshake
* Não mantém estado de sessão
* Não utiliza ACK

O scan UDP depende principalmente de **mensagens ICMP**, e não de respostas UDP.

---

## Técnicas de Scan Implementadas

### 1️⃣ TCP SYN Scan (Half-Open Scan)

**Função:** `tcp_syn_scan()`

#### Teoria

Esse scan envia apenas o **primeiro pacote do handshake TCP** (`SYN`) e analisa a resposta.

| Resposta     | Significado             |
| ------------ | ----------------------- |
| SYN-ACK      | Porta **aberta**        |
| RST          | Porta **fechada**       |
| Sem resposta | **Filtrada** (firewall) |

A conexão **nunca é totalmente estabelecida**, tornando o scan mais discreto.

#### Fluxo TCP

```
Scanner → SYN
Alvo    → SYN-ACK  (aberta)
Alvo    → RST      (fechada)
```

#### Lógica do Código

```python
pkt = IP(dst=ip_target) / TCP(dport=port, flags="S")
resp = sr1(pkt, timeout=TIMEOUT)
```

---

### 2️⃣ TCP ACK Scan (Detecção de Firewall)

**Função:** `ack_scan()`

#### Teoria

Esse scan **não determina** se a porta está aberta ou fechada.

Ele verifica **regras de firewall** enviando um pacote **ACK fora de contexto**.

| Resposta     | Significado            |
| ------------ | ---------------------- |
| RST          | Porta **não filtrada** |
| Sem resposta | **Filtrada**           |

Por quê?
Porque um host **deve responder com RST** a um ACK inválido **a menos que um firewall o bloqueie**.

#### Fluxo TCP

```
Scanner → ACK
Alvo    → RST   (sem firewall)
(sem resposta)  (firewall)
```

---

### 3️⃣ UDP Scan

**Função:** `udp_scan()`

#### Teoria

O UDP não confirma pacotes.
Portanto, **silêncio geralmente indica porta aberta**.

O único sinal confiável vem de **erros ICMP**.

| Resposta             | Significado            |
| -------------------- | ---------------------- |
| Resposta UDP         | **Aberta**             |
| ICMP tipo 3 código 3 | **Fechada**            |
| Sem resposta         | **Aberta ou Filtrada** |

#### Explicação do ICMP

* `Tipo 3` → Destino inalcançável
* `Código 3` → Porta inalcançável

Isso significa:

> “O host existe, mas não há nenhum serviço escutando nessa porta.”

---

### 4️⃣ TCP SYN Scan com Decoys (Evasão de IDS)

**Função:** `tcp_syn_scan_decoy()`

#### Teoria

Essa técnica envia **múltiplos pacotes SYN**:

* Vários com **IPs de origem falsos (decoys)**
* Um com o **IP real do scanner**

Para o alvo e seus logs, **todos os IPs parecem iguais**.

#### Fluxo TCP

```
IP Decoy 1 → SYN
IP Decoy 2 → SYN
IP Decoy 3 → SYN
IP Real    → SYN  ← resposta analisada
```

Apenas o **IP real** aguarda a resposta.

---

#### Por que funciona

* Logs de IDS/IPS mostram múltiplos atacantes
* Dificulta a atribuição da origem real
* Mesmo princípio usado pelo `nmap -D`

#### Limitações

* Requer privilégios de root
* Falha se a rede bloquear spoofing de IP
* IDS modernos podem detectar padrões de tempo

---

## 🧬 Resumo da Interpretação das Respostas

| Tipo de Scan | Pacote Enviado | Resposta | Interpretação     |
| ------------ | -------------- | -------- | ----------------- |
| SYN          | SYN            | SYN-ACK  | Aberta            |
| SYN          | SYN            | RST      | Fechada           |
| SYN          | SYN            | Nenhuma  | Filtrada          |
| ACK          | ACK            | RST      | Não filtrada      |
| ACK          | ACK            | Nenhuma  | Filtrada          |
| UDP          | UDP            | UDP      | Aberta            |
| UDP          | UDP            | ICMP 3/3 | Fechada           |
| UDP          | UDP            | Nenhuma  | Aberta / Filtrada |

---
