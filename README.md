# Vira Brasil · Placar de votos virados

Site da campanha com **placar compartilhado**: todos os votos virados registrados por qualquer visitante
são somados num banco de dados central e aparecem em tempo real para todo mundo.

## Como funciona

- `index.html` — o site (front-end)
- `server.js` — servidor Node.js que guarda os votos num banco SQLite (`votos.db`)
- A cada 15 segundos o site busca o placar atualizado do servidor

## Rodar no seu computador (teste local)

Precisa ter o **Node.js 18+** instalado (https://nodejs.org).

```bash
cd vira-brasil
npm install
npm start
```

Abra no navegador: http://localhost:3000

## Colocar no ar (produção)

### Opção recomendada: Render.com (grátis)

1. Crie uma conta em https://render.com
2. Suba esta pasta para um repositório no GitHub
3. No Render: **New → Blueprint** e aponte para o repositório (ele lê o `render.yaml`)
4. O Render instala, inicia e te dá uma URL tipo `https://vira-brasil.onrender.com`

> O `render.yaml` já configura um disco persistente para o banco não ser apagado a cada deploy.

### Apontar o domínio .com.br

1. Registre o domínio no https://registro.br (~R$ 40/ano)
2. No painel do Render: **Settings → Custom Domains → Add** e informe seu domínio
3. No registro.br, em **Editar DNS**, aponte conforme o Render indicar
   (geralmente um registro CNAME/ALIAS para o endereço `.onrender.com`)
4. O HTTPS é gerado automaticamente pelo Render

## Endpoints da API

- `GET  /api/placar`     → `{ total, porEstado: { UF: quantidade } }` (público)
- `POST /api/registrar`  → body `{ uf, nome, tel? }` → retorna o placar atualizado
- `GET  /api/export?chave=ADMIN_TOKEN` → exporta registros descriptografados (só admin)

## 🔒 Segurança implementada

1. **HTTPS/TLS** — todo o tráfego é criptografado (automático no Render) e forçado via HSTS.
2. **Criptografia em repouso (AES-256-GCM)** — nome e telefone são criptografados antes de
   gravar no banco. Se o arquivo `votos.db` for roubado, os dados pessoais ficam ilegíveis
   sem a `SECRET_KEY`. O GCM também detecta adulteração dos dados.
3. **Headers de segurança** — CSP, X-Frame-Options (anti-clickjacking), nosniff, HSTS, etc.
4. **Rate limiting** — máximo de 15 registros/min e 120 consultas/min por IP (anti-flood/spam).
5. **Sanitização** — remoção de caracteres de controle e limite de tamanho em todas as entradas.
6. **Mínimo de dados exposto** — o placar público mostra apenas números por estado.

### Variáveis de ambiente (defina no Render)

| Variável      | Para quê | Como gerar |
|---------------|----------|------------|
| `SECRET_KEY`  | Chave da criptografia dos dados | O `render.yaml` gera automaticamente. **Nunca mude depois** ou os dados antigos ficam ilegíveis. |
| `ADMIN_TOKEN` | Senha para exportar os registros | Gerada automaticamente. Veja no painel do Render. |
| `DB_PATH`     | Caminho do banco | Já configurado para o disco persistente. |

> Para rodar localmente com criptografia estável, defina você mesmo a `SECRET_KEY`:
> ```bash
> # Windows (PowerShell)
> $env:SECRET_KEY = "uma-chave-bem-longa-e-aleatoria-aqui"
> npm start
> ```

### Exportar os dados (uso administrativo)

Para ver os nomes/telefones descriptografados (auditoria), acesse:
```
https://SEU-SITE/api/export?chave=SEU_ADMIN_TOKEN
```

## Observações sobre dados pessoais (LGPD)

- O site exibe publicamente apenas o **total por estado**, nunca nome ou telefone.
- Nome e telefone ficam **criptografados** no banco — nem o administrador do servidor
  de hospedagem consegue lê-los sem a `SECRET_KEY`.
