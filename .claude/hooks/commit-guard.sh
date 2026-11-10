#!/usr/bin/env bash
# PreToolUse(Bash): bloquea `git commit` del agente si lo que se commitea trae
#  - un secreto reconocible,
#  - un correo fuera de ALLOWED_DOMAINS,
#  - un fichero .env (salvo plantillas: .env.example, .env.sample, .env.template).
# Cada bloqueo se registra en .claude/hooks/commit-guard.log (JSON por línea).
# Salida: exit 2 + motivo por stderr => Claude Code cancela la llamada y se lo muestra al agente.

# Dominios de correo permitidos (regex de dominio completo, separados por |).
ALLOWED_DOMAINS='gmail\.com|anthropic\.com|example\.(com|org|net)|users\.noreply\.github\.com'

# Patrones de secreto: "etiqueta|regex ERE".
SECRET_PATTERNS=(
  'AWS access key|AKIA[0-9A-Z]{16}'
  'Stripe key|[sr]k_(live|test)_[0-9A-Za-z]{16,}'
  'Anthropic/OpenAI key|sk-(ant-)?[A-Za-z0-9_-]{20,}'
  'GitHub token|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}'
  'Slack token|xox[abprs]-[A-Za-z0-9-]{10,}'
  'Google API key|AIza[0-9A-Za-z_-]{35}'
  'clave privada|-----BEGIN ([A-Z]+ )?PRIVATE KEY-----'
  'credencial literal|(password|passwd|secret|api[_-]?key|token)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"'$\{][^"'"'"']{11,}["'"'"']'
)

input=$(cat)
cmd=$(jq -r '.tool_input.command // empty' <<<"$input")
session=$(jq -r '.session_id // "?"' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")

# Solo nos interesan los comandos que contienen `git ... commit`.
grep -Eq '(^|[;&|(]|[[:space:]])git([[:space:]]+-[^[:space:]]+([[:space:]]+[^[:space:]-][^[:space:]]*)?)*[[:space:]]+commit([[:space:]]|$)' <<<"$cmd" || exit 0

[ -n "$cwd" ] && cd "$cwd" 2>/dev/null
log="${CLAUDE_PROJECT_DIR:-$PWD}/.claude/hooks/commit-guard.log"
findings=()

report() { # tipo fichero detalle
  findings+=("$1|$2|$3")
  jq -cn --arg ts "$(date +%Y-%m-%dT%H:%M:%S)" --arg s "$session" --arg t "$1" --arg f "$2" --arg d "$3" \
    '{ts:$ts,session:$s,tipo:$t,fichero:$f,detalle:$d}' >>"$log"
}

mask() { local s=$1; printf '%s…(%d car.)' "${s:0:4}" "${#s}"; }

# Qué se commitea: con -a/--all/-am entra también lo tracked modificado.
if grep -Eq '(^|[[:space:]])(--all|-[a-zA-Z]*a[a-zA-Z]*)([[:space:]]|$)' <<<"$cmd"; then
  diff_args=(HEAD)
else
  diff_args=(--cached)
fi

# 0) Escribir ficheros y commitear en la misma llamada impide auditar el commit.
stripped=$(perl -0pe 's/"(?:[^"\\]|\\.)*"|\x27[^\x27]*\x27//gs; s/\d*>&\d+//g; s#\d*>>?\s*/dev/null##g' <<<"$cmd")
if grep -Eq '(^|[^<>])>>?[[:space:]]*[^[:space:]&>]|\btee\b|\bsed[[:space:]]+-[a-zA-Z]*i' <<<"$stripped"; then
  report "comando mixto" "<comando>" "escribe ficheros y commitea en una sola llamada; sepáralos para que el commit se pueda auditar"
fi

# 1) Ficheros .env
while IFS= read -r f; do
  [ -z "$f" ] && continue
  b=${f##*/}
  case "$b" in
    .env.example | .env.sample | .env.template) ;;
    .env | .env.* | *.env) report "fichero .env" "$f" "no se commitean ficheros .env" ;;
  esac
done < <(git diff "${diff_args[@]}" --name-only --diff-filter=ACMR 2>/dev/null)

# 2) Secretos y correos en las líneas añadidas (y en el mensaje del commit).
scan() { # fichero texto
  local file=$1 text=$2 p label re hit mail dom
  for p in "${SECRET_PATTERNS[@]}"; do
    label=${p%%|*}; re=${p#*|}
    hit=$(grep -Eio -m1 -- "$re" <<<"$text" | head -1)
    [ -n "$hit" ] && report "secreto" "$file" "$label: $(mask "$hit")"
  done
  while IFS= read -r mail; do
    [ -z "$mail" ] && continue
    dom=${mail#*@}
    grep -Eiq "^(${ALLOWED_DOMAINS})$" <<<"$dom" || report "correo no permitido" "$file" "$mail"
  done < <(grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' <<<"$text" | sort -u)
}

while IFS=$'\t' read -r file text; do
  [ -n "$file" ] && scan "$file" "$text"
done < <(git diff "${diff_args[@]}" -U0 --no-color --diff-filter=ACMR 2>/dev/null |
  awk '/^\+\+\+ b\//{f=substr($0,7);next} /^\+\+\+ /{next} /^\+/{print f "\t" substr($0,2)}')

scan "<mensaje del commit>" "$cmd"

if [ ${#findings[@]} -gt 0 ]; then
  {
    echo "Commit bloqueado por commit-guard (${#findings[@]} hallazgo/s). Registrado en .claude/hooks/commit-guard.log:"
    for x in "${findings[@]}"; do IFS='|' read -r t f d <<<"$x"; echo "  - [$t] $f: $d"; done
    echo "Quita lo señalado del commit (git reset <fichero>, o sustitúyelo por un valor/placeholder permitido) y reintenta."
  } >&2
  exit 2
fi
exit 0
