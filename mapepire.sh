#!/usr/bin/env bash
#
# mapepire.sh - a pure bash client for Mapepire (https://mapepire-ibmi.github.io/)
#
# Implements the Mapepire protocol (https://github.com/Mapepire-IBMi/mapepire-protocol)
# using nothing but bash builtins: the HTTP upgrade, WebSocket framing and masking,
# Base64, SHA-1, JSON encoding/parsing and result rendering are all done in bash.
#
# Two transports are supported:
#
#   server mode   wss://HOST:PORT/db/ -- TLS is mandatory. Since bash cannot speak
#                 TLS, `openssl s_client` is used purely as an encrypted byte pipe.
#   single mode   a Mapepire server started with --single, speaking newline-delimited
#                 JSON over stdin/stdout (e.g. locally on IBM i, or through ssh).
#
# Run it as a command (see --help), or source it and use the mp_* functions:
#
#   source mapepire.sh
#   MP_HOST=myibmi MP_USER=me MP_PASSWORD=secret
#   mp_connect || { echo "$MP_ERROR"; exit 1; }
#   mp_sql "select * from qiws.qcustcdt" && mp_print_result table
#   mp_close
#
# Requires bash 4.2 or newer.

if [ -z "${BASH_VERSINFO-}" ] || [ "${BASH_VERSINFO[0]}" -lt 4 ] ||
    { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -lt 2 ]; }; then
    echo "mapepire.sh: bash 4.2 or newer is required" >&2
    return 1 2>/dev/null || exit 1
fi

shopt -s extglob

MP_VERSION=1.0.0

# ---------------------------------------------------------------------------
# Settings -- assign these before calling mp_connect
# ---------------------------------------------------------------------------
: "${MP_HOST:=}"                     # server host name (server mode)
: "${MP_PORT:=8076}"                 # server port (server mode)
: "${MP_USER:=}"                     # IBM i user profile (server mode)
: "${MP_PASSWORD:=}"                 # password (server mode)
: "${MP_CA:=}"                       # PEM file of trusted certificate(s); empty = system store
: "${MP_TLS_VERIFY:=1}"              # 0 = skip certificate verification (insecure!)
: "${MP_SINGLE:=}"                   # command that runs a single-mode server; enables single mode
: "${MP_PROPS:=}"                    # JDBC properties, e.g. "naming=system;libraries=MYLIB"
: "${MP_TECHNIQUE:=}"                # "tcp" or "cli"; empty = server default
: "${MP_APPLICATION:=mapepire-bash}" # application name for job tracking
: "${MP_TERSE:=0}"                   # 1 = result rows as arrays instead of objects
: "${MP_ROWS:=}"                     # rows per block; empty = server default (1000)
: "${MP_DEBUG:=0}"                   # 1 = trace protocol messages to stderr

# ---------------------------------------------------------------------------
# Results -- set by the mp_* functions
# ---------------------------------------------------------------------------
MP_ID=           # correlation id of the last request (also the cursor handle)
MP_RESPONSE=     # raw JSON text of the last response
MP_ERROR=        # error message of the last failed operation
MP_JOB=          # IBM i job name of the database connection
declare -gA MP_JSON=()  # last response, flattened: "path" -> raw JSON token
declare -ga MP_COLS=() MP_NUMCOLS=() MP_CELLS=() MP_NULLS=()  # columns of the last result set; rendered rows

# Internal state
MP__KIND=        # "tls", "single", or empty when disconnected
MP__IN=          # fd we read the server from
MP__OUT=         # fd we write the server to
MP__PID=         # pid of the transport process
MP__SEQ=0        # request id counter
MP__MSG=         # last raw message received
MP__DATA=
declare -ga MP__BYTES=() MP__HEX=()
for ((MP__i = 0; MP__i < 256; MP__i++)); do printf -v 'MP__HEX[MP__i]' '\\x%02x' "$MP__i"; done
unset MP__i
MP__B64=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
MP__WS_GUID=258EAFA5-E914-47DA-95CA-C5AB0DC85B11

mp__debug() { [[ $MP_DEBUG == 1 ]] && printf '[%s] %s\n' "${EPOCHREALTIME-}" "$*" >&2; return 0; }
mp__fail() { MP_ERROR=$1; return 1; }

# ---------------------------------------------------------------------------
# Bytes, Base64, SHA-1, randomness
# ---------------------------------------------------------------------------

# REPLY = a random 32-bit number (SRANDOM uses the OS CSPRNG on bash 5.1+)
mp__rand() {
    if [[ -n ${SRANDOM-} ]]; then REPLY=$SRANDOM; else REPLY=$(( (RANDOM << 17 ^ RANDOM << 2 ^ RANDOM) & 0xFFFFFFFF )); fi
}

# MP__BYTES = the byte values of string $1
mp__str_bytes() {
    local LC_ALL=C s=$1 chunk c
    local -i i n
    MP__BYTES=()
    # Work in small chunks: ${s:i:1} costs O(length of s) per call.
    while [[ -n $s ]]; do
        chunk=${s:0:256} s=${s:256} n=${#chunk}
        for ((i = 0; i < n; i++)); do
            printf -v c '%d' "'${chunk:i:1}"
            MP__BYTES+=("$c")
        done
    done
}

# REPLY = Base64 of the bytes in MP__BYTES
mp__b64() {
    local out= t=$MP__B64
    local -i i n=${#MP__BYTES[@]} v
    for ((i = 0; i < n; i += 3)); do
        v=$(( MP__BYTES[i] << 16 | ${MP__BYTES[i+1]:-0} << 8 | ${MP__BYTES[i+2]:-0} ))
        out+=${t:v >> 18 & 63:1}${t:v >> 12 & 63:1}
        if (( i + 1 < n )); then out+=${t:v >> 6 & 63:1}; else out+='='; fi
        if (( i + 2 < n )); then out+=${t:v & 63:1}; else out+='='; fi
    done
    REPLY=$out
}

# MP__BYTES = SHA-1 digest (20 bytes) of the bytes in MP__BYTES
mp__sha1() {
    local -a m=("${MP__BYTES[@]}") w
    local -i ml=$(( ${#m[@]} * 8 )) i j n a b c d e f k t M=0xFFFFFFFF
    local -i h0=0x67452301 h1=0xEFCDAB89 h2=0x98BADCFE h3=0x10325476 h4=0xC3D2E1F0
    m+=(128)
    while (( ${#m[@]} % 64 != 56 )); do m+=(0); done
    for ((i = 56; i >= 0; i -= 8)); do m+=($(( ml >> i & 255 ))); done
    n=${#m[@]}
    for ((j = 0; j < n; j += 64)); do
        for ((i = 0; i < 16; i++)); do
            w[i]=$(( m[j+4*i] << 24 | m[j+4*i+1] << 16 | m[j+4*i+2] << 8 | m[j+4*i+3] ))
        done
        for ((i = 16; i < 80; i++)); do
            t=$(( w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16] ))
            w[i]=$(( (t << 1 | t >> 31) & M ))
        done
        a=h0 b=h1 c=h2 d=h3 e=h4
        for ((i = 0; i < 80; i++)); do
            if (( i < 20 )); then f=$(( (b & c) | (~b & d) )) k=0x5A827999
            elif (( i < 40 )); then f=$(( b ^ c ^ d )) k=0x6ED9EBA1
            elif (( i < 60 )); then f=$(( (b & c) | (b & d) | (c & d) )) k=0x8F1BBCDC
            else f=$(( b ^ c ^ d )) k=0xCA62C1D6
            fi
            t=$(( ((a << 5 | a >> 27) + f + e + k + w[i]) & M ))
            e=d d=c c=$(( (b << 30 | b >> 2) & M )) b=a a=t
        done
        h0=$(( (h0 + a) & M )) h1=$(( (h1 + b) & M )) h2=$(( (h2 + c) & M ))
        h3=$(( (h3 + d) & M )) h4=$(( (h4 + e) & M ))
    done
    MP__BYTES=()
    for t in h0 h1 h2 h3 h4; do
        MP__BYTES+=($(( t >> 24 & 255 )) $(( t >> 16 & 255 )) $(( t >> 8 & 255 )) $(( t & 255 )))
    done
}

# REPLY = UTF-8 encoding of code point $1
mp__utf8() {
    local -i c=$1
    local f
    if (( c < 0x80 )); then f=${MP__HEX[c]}
    elif (( c < 0x800 )); then f=${MP__HEX[0xC0 | c >> 6]}${MP__HEX[0x80 | c & 63]}
    elif (( c < 0x10000 )); then f=${MP__HEX[0xE0 | c >> 12]}${MP__HEX[0x80 | c >> 6 & 63]}${MP__HEX[0x80 | c & 63]}
    else f=${MP__HEX[0xF0 | c >> 18]}${MP__HEX[0x80 | c >> 12 & 63]}${MP__HEX[0x80 | c >> 6 & 63]}${MP__HEX[0x80 | c & 63]}
    fi
    printf -v REPLY "$f"
}

# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

# REPLY = $1 as a quoted JSON string
mp_json_str() {
    local LC_ALL=C s=$1 bs='\' q='"' c
    local -i i
    s=${s//"$bs"/"$bs$bs"}
    s=${s//"$q"/"$bs$q"}
    if [[ $s == *[$'\x01'-$'\x1f']* ]]; then
        s=${s//$'\n'/"\\n"}
        s=${s//$'\r'/"\\r"}
        s=${s//$'\t'/"\\t"}
        for ((i = 1; i < 32; i++)); do
            printf -v c "${MP__HEX[i]}"
            [[ $s == *"$c"* ]] && s=${s//"$c"/"$(printf '\\u%04x' "$i")"}
        done
    fi
    REPLY=$q$s$q
}

# REPLY = JSON array of the arguments as strings, e.g. ["a","b"]
mp_json_array() {
    local out= v
    for v in "$@"; do mp_json_str "$v"; out+=${out:+,}$REPLY; done
    REPLY="[$out]"
}

# Note on performance: bash's own pattern operators (${s%%pat*}, ${s#*pat},
# ${s//pat/rep}) rescan the remainder of the string on every step, which is
# quadratic on large values. The JSON code below instead tokenizes with word
# splitting (one linear pass in C) and only walks short pieces character by
# character.

# Run "$@" with globbing disabled (word splitting is used for tokenizing)
mp__noglob() {
    local rc
    if [[ $- == *f* ]]; then "$@"; return; fi
    set -f
    "$@"
    rc=$?
    set +f
    return $rc
}

# REPLY = the decoded value of raw JSON string token $1 (including its quotes)
mp__unescape() { mp__noglob mp__unescape_body "${1:1:${#1}-2}"; }

# REPLY = the decoded value of JSON string body $1 (without quotes)
mp__unescape_body() {
    if [[ $1 != *'\'* ]]; then REPLY=$1; return 0; fi
    local LC_ALL=C IFS='\' out p c
    local -a f
    local -i j n cp lo
    # Split on backslashes: each field then starts with an escape code, except
    # that an empty field is an escaped backslash (the next field is plain text).
    # The trailing " " keeps a trailing empty field from being dropped.
    f=($1" ")
    n=${#f[@]}
    out=${f[0]}
    for ((j = 1; j < n; j++)); do
        p=${f[j]}
        if [[ -z $p ]]; then
            j+=1
            out+='\'${f[j]}
            continue
        fi
        c=${p:0:1} p=${p:1}
        case $c in
            n) out+=$'\n' ;;
            t) out+=$'\t' ;;
            r) out+=$'\r' ;;
            b) out+=$'\b' ;;
            f) out+=$'\f' ;;
            u)
                cp=16#${p:0:4} p=${p:4}
                # UTF-16 surrogate pair: \uD83D\uDE00
                if (( cp >= 0xD800 && cp < 0xDC00 )) && [[ -z $p && ${f[j+1]} == u[dD][c-fC-F]??* ]]; then
                    j+=1
                    lo=16#${f[j]:1:4} p=${f[j]:5}
                    cp=$(( 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00) ))
                fi
                mp__utf8 "$cp"
                out+=$REPLY
                ;;
            *) out+=$c ;;  # \" \/
        esac
        out+=$p
    done
    REPLY=${out% }
}

# Parse JSON text $1 into MP_JSON. Each scalar is stored under its path
# (object keys and array indexes joined by "."), as its raw JSON token:
# strings keep their quotes, so null and "null" stay distinguishable.
# Each array also gets "<path>.#" = its length.
#
#   {"id":"1","data":[[1,"a"]]}  ->  id="1"  data.#=1  data.0.#=2  data.0.0=1  data.0.1="a"
mp_parse() { mp__noglob mp__parse "$1"; }

mp__parse() {
    local LC_ALL=C IFS='"' s p c lit key= path endlit='[]}[:space:]]*'
    local -a parts pieces ctype=() cpath=()
    local -ai cidx=() cempty=()
    local -i i j k n np depth=0 want_key=0 in_str=0
    unset MP_JSON
    declare -gA MP_JSON=()

    # Split on quotes: parts then alternate between structural text and string
    # bodies. A quote preceded by an odd number of backslashes was escaped, so
    # such a string part is joined with the next one.
    parts=($1" ")
    n=${#parts[@]}
    for ((i = 0; i < n; i++)); do
        if (( in_str )); then
            s=${parts[i]} p=$s
            # Only the newest part (p) is inspected: s grows, and slicing it is O(length)
            while [[ ${p: -1} == '\' ]]; do
                k=1
                while (( k < ${#p} )) && [[ ${p:${#p}-k-1:1} == '\' ]]; do k+=1; done
                (( k % 2 )) || break
                (( i + 1 < n )) || return 1
                i+=1
                p=${parts[i]}
                s+='"'$p
            done
            (( i + 1 < n )) || return 1   # unterminated string
            if (( want_key )); then
                mp__unescape_body "$s"
                key=$REPLY want_key=0
            else
                if (( depth == 0 )); then path=_
                elif [[ ${ctype[depth]} == '[' ]]; then path=${cpath[depth]}${cidx[depth]} cempty[depth]=0
                else path=${cpath[depth]}$key
                fi
                MP_JSON[$path]=\"$s\"
            fi
            in_str=0
            continue
        fi

        # Structural text: split on commas into short pieces
        IFS=,
        pieces=(${parts[i]}" ")
        IFS='"'
        np=${#pieces[@]}
        for ((j = 0; j < np; j++)); do
            if (( j )); then
                if [[ ${ctype[depth]} == '[' ]]; then cidx[depth]+=1; else want_key=1; fi
            fi
            p=${pieces[j]}
            while [[ -n $p ]]; do
                c=${p:0:1}
                case $c in
                    [[:space:]] | :)
                        p=${p:1} ;;
                    '{' | '[')
                        if (( depth == 0 )); then path=_
                        elif [[ ${ctype[depth]} == '[' ]]; then path=${cpath[depth]}${cidx[depth]} cempty[depth]=0
                        else path=${cpath[depth]}$key
                        fi
                        depth+=1
                        ctype[depth]=$c cpath[depth]=$path. cidx[depth]=0 cempty[depth]=1
                        (( depth == 1 )) && cpath[depth]=
                        [[ $c == '{' ]] && want_key=1
                        p=${p:1} ;;
                    '}' | ']')
                        (( depth > 0 )) || return 1
                        if [[ $c == ']' ]]; then
                            MP_JSON[${cpath[depth]}#]=$(( cempty[depth] ? 0 : cidx[depth] + 1 ))
                        fi
                        depth=depth-1 want_key=0
                        p=${p:1} ;;
                    *)
                        lit=${p%%$endlit}
                        [[ $lit == @(true|false|null|?(-)[0-9]*) ]] || return 1
                        if (( depth == 0 )); then path=_
                        elif [[ ${ctype[depth]} == '[' ]]; then path=${cpath[depth]}${cidx[depth]} cempty[depth]=0
                        else path=${cpath[depth]}$key
                        fi
                        MP_JSON[$path]=$lit
                        p=${p:${#lit}} ;;
                esac
            done
        done
        in_str=1
    done
    (( depth == 0 ))
}

# REPLY = decoded value at path $1 of the last response (strings unescaped).
# Returns 1 if the path is absent or null.
mp_get() {
    REPLY=
    [[ -n ${MP_JSON[$1]+x} ]] || return 1
    local raw=${MP_JSON[$1]}
    case $raw in
        null) return 1 ;;
        \"*) mp__unescape "$raw" ;;
        *) REPLY=$raw ;;
    esac
}

# REPLY = length of the array at path $1 (0 if absent)
mp_count() { REPLY=${MP_JSON[${1:+$1.}#]:-0}; }

# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

mp__tls_args() {
    MP__TLS_ARGS=(s_client -connect "$MP_HOST:$MP_PORT")
    if [[ $MP_TLS_VERIFY != 0 ]]; then
        MP__TLS_ARGS+=(-verify_return_error)
        if [[ $MP_HOST == +([0-9.]) || $MP_HOST == *:* ]]; then
            MP__TLS_ARGS+=(-verify_ip "$MP_HOST")
        else
            MP__TLS_ARGS+=(-verify_hostname "$MP_HOST")
        fi
        [[ -n $MP_CA ]] && MP__TLS_ARGS+=(-CAfile "$MP_CA")
    fi
}

mp__open_tls() {
    [[ -n $MP_HOST ]] || mp__fail "no host specified" || return 1
    command -v openssl >/dev/null 2>&1 || mp__fail "openssl is required for TLS (server mode) but was not found in PATH" || return 1
    [[ -z $MP_CA || -r $MP_CA ]] || mp__fail "cannot read CA file: $MP_CA" || return 1
    mp__tls_args
    # -quiet: no session chatter on stdout, and ignore EOF on stdin
    coproc MP__CO { exec openssl "${MP__TLS_ARGS[@]}" -quiet 2>/dev/null; }
    MP__PID=$MP__CO_PID
    exec {MP__IN}<&"${MP__CO[0]}" {MP__OUT}>&"${MP__CO[1]}"
    MP__KIND=tls
}

mp__open_single() {
    coproc MP__CO { eval "exec $MP_SINGLE"; }
    MP__PID=$MP__CO_PID
    exec {MP__IN}<&"${MP__CO[0]}" {MP__OUT}>&"${MP__CO[1]}"
    MP__KIND=single
}

mp__close_transport() {
    [[ -n $MP__KIND ]] || return 0
    local fd
    exec {MP__OUT}>&- {MP__IN}<&-
    for fd in ${MP__CO[1]-} ${MP__CO[0]-}; do exec {fd}<&-; done
    if [[ -n $MP__PID ]]; then
        [[ $MP__KIND == tls ]] && kill "$MP__PID" 2>/dev/null
        wait "$MP__PID" 2>/dev/null
    fi
    MP__KIND= MP__IN= MP__OUT= MP__PID=
}

# Explain why a TLS connection failed by running a short-lived probe.
mp__tls_diagnose() {
    local line msg= all=
    mp__tls_args
    while IFS= read -r line; do
        line=${line%$'\r'}
        all+="  $line"$'\n'
        [[ $line == *[Ee]rr* || $line == *[Vv]erif* || $line == *refused* || $line == *[Uu]nable* ]] && msg+="  $line"$'\n'
    done < <(openssl "${MP__TLS_ARGS[@]}" -brief </dev/null 2>&1)
    msg=${msg:-$all}
    MP_ERROR="TLS connection to $MP_HOST:$MP_PORT failed"${msg:+$':\n'"${msg%$'\n'}"}
    if [[ $msg == *[Vv]erif* ]]; then
        MP_ERROR+=$'\n'"  Hint: Mapepire servers often use a self-signed certificate. Save it with"
        MP_ERROR+=$'\n'"        --print-cert > server.pem, check it, then use --ca server.pem."
    fi
    return 1
}

mp__alive() { [[ -n $MP__KIND ]] && { [[ -z $MP__PID ]] || kill -0 "$MP__PID" 2>/dev/null; }; }

mp__lost() {
    local kind=$MP__KIND
    mp__close_transport
    if [[ $kind == single ]]; then MP_ERROR="the single-mode server exited"; else MP_ERROR="connection to the server was lost"; fi
    return 1
}

# ---------------------------------------------------------------------------
# WebSocket (RFC 6455)
# ---------------------------------------------------------------------------

# Send one masked frame with opcode $1 and payload MP__BYTES
mp__ws_frame() {
    local LC_ALL=C f
    local -i op=$1 n=${#MP__BYTES[@]} i m
    local -a k
    f=${MP__HEX[0x80 | op]}
    if (( n < 126 )); then
        f+=${MP__HEX[0x80 | n]}
    elif (( n < 65536 )); then
        f+=${MP__HEX[254]}${MP__HEX[n >> 8]}${MP__HEX[n & 255]}
    else
        f+=${MP__HEX[255]}
        for ((i = 56; i >= 0; i -= 8)); do f+=${MP__HEX[n >> i & 255]}; done
    fi
    mp__rand
    m=$REPLY k=($(( m >> 24 & 255 )) $(( m >> 16 & 255 )) $(( m >> 8 & 255 )) $(( m & 255 )))
    f+=${MP__HEX[k[0]]}${MP__HEX[k[1]]}${MP__HEX[k[2]]}${MP__HEX[k[3]]}
    for ((i = 0; i < n; i++)); do f+=${MP__HEX[MP__BYTES[i] ^ k[i & 3]]}; done
    printf "$f" >&"$MP__OUT" 2>/dev/null
}

# REPLY = value of the next byte from the server
mp__getc() {
    local LC_ALL=C c
    IFS= read -r -d '' -n 1 -u "$MP__IN" c || return 1
    if [[ -z $c ]]; then REPLY=0; else printf -v REPLY '%d' "'$c"; fi
}

# MP__MSG = the next complete text message. Answers pings; handles close.
mp__ws_recv() {
    local LC_ALL=C msg= reason
    local -i b0 b1 op fin len i code
    local -a pl
    while :; do
        mp__getc || return 1; b0=$REPLY
        mp__getc || return 1; b1=$REPLY
        fin=$(( b0 >> 7 )) op=$(( b0 & 15 )) len=$(( b1 & 127 ))
        (( b1 & 128 )) && { mp__close_transport; mp__fail "protocol error: server sent a masked frame"; return 1; }
        if (( len == 126 )); then
            mp__getc || return 1; len=$(( REPLY << 8 ))
            mp__getc || return 1; len+=$REPLY
        elif (( len == 127 )); then
            len=0
            for ((i = 0; i < 8; i++)); do mp__getc || return 1; len=$(( len << 8 | REPLY )); done
        fi
        if (( op >= 8 )); then
            pl=()
            for ((i = 0; i < len; i++)); do mp__getc || return 1; pl+=("$REPLY"); done
            case $op in
                8)  code=0 reason=
                    (( len >= 2 )) && code=$(( pl[0] << 8 | pl[1] ))
                    for ((i = 2; i < len; i++)); do reason+=${MP__HEX[pl[i]]}; done
                    printf -v reason "$reason"
                    MP__BYTES=("${pl[@]:0:2}")
                    mp__ws_frame 8
                    mp__close_transport
                    mp__fail "server closed the connection (code $code${reason:+: $reason})"
                    return 1 ;;
                9)  MP__BYTES=("${pl[@]}")
                    mp__ws_frame 10 ;;
            esac
            continue
        fi
        if (( len > 0 )); then
            IFS= read -r -N "$len" -u "$MP__IN" MP__DATA || return 1
            msg+=$MP__DATA
        fi
        if (( fin )); then MP__MSG=$msg; return 0; fi
    done
}

mp__ws_handshake() {
    local LC_ALL=C key auth expect line status name
    local -A hdr=()
    local -i i
    MP__BYTES=()
    for ((i = 0; i < 4; i++)); do
        mp__rand
        MP__BYTES+=($(( REPLY >> 24 & 255 )) $(( REPLY >> 16 & 255 )) $(( REPLY >> 8 & 255 )) $(( REPLY & 255 )))
    done
    mp__b64; key=$REPLY
    mp__str_bytes "$MP_USER:$MP_PASSWORD"; mp__b64; auth=$REPLY

    printf 'GET /db/ HTTP/1.1\r\nHost: %s:%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Basic %s\r\nUser-Agent: mapepire-bash/%s\r\n\r\n' \
        "$MP_HOST" "$MP_PORT" "$key" "$auth" "$MP_VERSION" >&"$MP__OUT" 2>/dev/null

    if ! IFS= read -r -u "$MP__IN" status; then
        mp__close_transport
        mp__tls_diagnose
        return 1
    fi
    status=${status%$'\r'}
    while IFS= read -r -u "$MP__IN" line; do
        line=${line%$'\r'}
        [[ -z $line ]] && break
        name=${line%%:*}
        line=${line#*:}
        hdr[${name,,}]=${line# }
    done
    mp__debug "<< $status"

    if [[ $status != HTTP/1.[01]\ 101* ]]; then
        mp__close_transport
        case $status in
            *\ 401* | *\ 403*) mp__fail "authentication failed for user $MP_USER ($status)" ;;
            *) mp__fail "WebSocket upgrade failed: ${status:-no response}" ;;
        esac
        return 1
    fi

    mp__str_bytes "$key$MP__WS_GUID"; mp__sha1; mp__b64; expect=$REPLY
    if [[ ${hdr[sec-websocket-accept]-} != "$expect" ]]; then
        mp__close_transport
        mp__fail "WebSocket upgrade failed: bad Sec-WebSocket-Accept"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

mp__send() {
    mp__alive || mp__lost || return 1
    mp__debug ">> $1"
    if [[ $MP__KIND == single ]]; then
        printf '%s\n' "$1" >&"$MP__OUT" 2>/dev/null || mp__lost
    else
        mp__str_bytes "$1"
        mp__ws_frame 1 || mp__lost
    fi
}

mp__recv() {
    if [[ $MP__KIND == single ]]; then
        while :; do
            IFS= read -r -u "$MP__IN" MP__MSG || { mp__lost; return 1; }
            [[ $MP__MSG == '{'* ]] && break
            mp__debug "?? $MP__MSG"
        done
    else
        mp__ws_recv || { [[ -n $MP__KIND ]] && mp__lost; return 1; }
    fi
    mp__debug "<< $MP__MSG"
}

# Send a request of type $1 with extra JSON members $2 (e.g. '"sql":"values 1"')
# and wait for its response. Returns 0 if the server reported success; otherwise
# 1 with MP_ERROR set. The response is in MP_RESPONSE and MP_JSON.
mp_request() {
    local type=$1 fields=${2-} id
    [[ -n $MP__KIND ]] || mp__fail "not connected" || return 1
    MP__SEQ=$(( MP__SEQ + 1 ))
    id=$MP__SEQ MP_ID=$MP__SEQ
    mp__send "{\"id\":\"$id\",\"type\":\"$type\"${fields:+,$fields}}" || return 1
    while :; do
        mp__recv || return 1
        mp_parse "$MP__MSG" || mp__fail "could not parse server response: ${MP__MSG:0:200}" || return 1
        [[ ${MP_JSON[id]-} == "\"$id\"" ]] && break
        mp__debug "ignoring message for another request: ${MP_JSON[id]-}"
    done
    MP_RESPONSE=$MP__MSG
    # Remember the columns: later blocks of the same cursor (sqlmore) carry no metadata
    [[ -n ${MP_JSON[metadata.columns.#]+x} ]] && mp__columns metadata
    [[ ${MP_JSON[success]-} == true ]] && { MP_ERROR=; return 0; }
    mp_get error || REPLY="request failed"
    MP_ERROR=$REPLY
    if mp_get sql_state; then
        MP_ERROR+=" [SQLSTATE $REPLY"
        mp_get sql_rc && MP_ERROR+=", SQLCODE $REPLY"
        MP_ERROR+="]"
    fi
    return 1
}

# Builds the optional '"rows":N' and '"terse":true' members
mp__opts() {
    local rows=${1:-$MP_ROWS}
    REPLY=
    [[ -n $rows ]] && REPLY+=",\"rows\":$(( rows ))"
    [[ $MP_TERSE == 1 ]] && REPLY+=',"terse":true'
}

# Open the transport and the database connection.
mp_connect() {
    local f=
    mp__close_transport
    MP_ERROR= MP_JOB=
    if [[ -n $MP_SINGLE ]]; then
        mp__open_single || return 1
    else
        mp__open_tls && mp__ws_handshake || return 1
    fi
    if [[ -n $MP_PROPS ]]; then mp_json_str "$MP_PROPS"; f+=",\"props\":$REPLY"; fi
    if [[ -n $MP_TECHNIQUE ]]; then mp_json_str "$MP_TECHNIQUE"; f+=",\"technique\":$REPLY"; fi
    if [[ -n $MP_APPLICATION ]]; then mp_json_str "$MP_APPLICATION"; f+=",\"application\":$REPLY"; fi
    if ! mp_request connect "${f#,}"; then
        local err=$MP_ERROR
        mp__close_transport
        MP_ERROR=$err
        return 1
    fi
    mp_get job && MP_JOB=$REPLY
    return 0
}

# Send exit and shut the transport down.
mp_close() {
    [[ -n $MP__KIND ]] || return 0
    mp_request exit >/dev/null 2>&1
    if [[ $MP__KIND == tls ]] && mp__alive; then
        MP__BYTES=(3 232)   # close, status 1000 (normal)
        mp__ws_frame 8
    fi
    mp__close_transport
    return 0
}

mp_connected() { mp__alive; }

# mp_sql SQL [ROWS]
mp_sql() {
    local sql=$1
    mp_json_str "$sql"; sql=$REPLY
    mp__opts "${2-}"
    mp_request sql "\"sql\":$sql$REPLY"
}

# mp_prepare_sql SQL
mp_prepare_sql() {
    mp_json_str "$1"
    local f="\"sql\":$REPLY"
    [[ $MP_TERSE == 1 ]] && f+=',"terse":true'
    mp_request prepare_sql "$f"
}

# mp_prepare_sql_execute SQL PARAMS_JSON [ROWS]    e.g. mp_prepare_sql_execute "... = ?" '["A01"]'
mp_prepare_sql_execute() {
    local sql
    mp_json_str "$1"; sql=$REPLY
    mp__opts "${3-}"
    mp_request prepare_sql_execute "\"sql\":$sql,\"parameters\":${2:-[]}$REPLY"
}

# mp_execute CONT_ID PARAMS_JSON [ROWS]
mp_execute() {
    local cont
    mp_json_str "$1"; cont=$REPLY
    mp__opts "${3-}"
    mp_request execute "\"cont_id\":$cont,\"parameters\":${2:-[]}$REPLY"
}

# mp_sqlmore CONT_ID [ROWS]
mp_sqlmore() {
    local cont rows=${2:-$MP_ROWS}
    mp_json_str "$1"; cont=$REPLY
    mp_request sqlmore "\"cont_id\":$cont${rows:+,\"rows\":$(( rows ))}"
}

# mp_sqlclose CONT_ID
mp_sqlclose() { mp_json_str "$1"; mp_request sqlclose "\"cont_id\":$REPLY"; }

# mp_cl COMMAND
mp_cl() {
    mp_json_str "$1"
    local f="\"cmd\":$REPLY"
    [[ $MP_TERSE == 1 ]] && f+=',"terse":true'
    mp_request cl "$f"
}

# mp_dove SQL [RUN(true|false)] [ROWS]
mp_dove() {
    local sql
    mp_json_str "$1"; sql=$REPLY
    mp__opts "${3-}"
    mp_request dove "\"sql\":$sql${2:+,\"run\":$2}$REPLY"
}

mp_ping() { mp_request ping; }
mp_getdbjob() { mp_request getdbjob; }
mp_getversion() { mp_request getversion; }
mp_gettracedata() { mp_request gettracedata; }

# mp_setconfig [tracedest=FILE|IN_MEM] [tracelevel=...] [jtopentracedest=...] [jtopentracelevel=...]
mp_setconfig() {
    local f= kv
    for kv in "$@"; do
        [[ $kv == *=* ]] || mp__fail "setconfig: expected key=value, got '$kv'" || return 1
        mp_json_str "${kv#*=}"
        f+=",\"${kv%%=*}\":$REPLY"
    done
    mp_request setconfig "${f#,}"
}

# ---------------------------------------------------------------------------
# Result rendering
# ---------------------------------------------------------------------------

# MP_COLS / MP_NUMCOLS = column names / numeric flags from metadata at path $1
mp__columns() {
    local m=${1:-metadata}
    local -i i n
    MP_COLS=() MP_NUMCOLS=()
    mp_count "$m.columns"; n=$REPLY
    for ((i = 0; i < n; i++)); do
        mp_get "$m.columns.$i.name" || mp_get "$m.columns.$i.label"
        MP_COLS+=("$REPLY")
        mp_get "$m.columns.$i.type"
        case ${REPLY^^} in
            *INT* | DECIMAL | NUMERIC | DOUBLE | REAL | FLOAT | DECFLOAT) MP_NUMCOLS+=(1) ;;
            *) MP_NUMCOLS+=(0) ;;
        esac
    done
}

# Append the rows of the array at path $1 to MP_CELLS / MP_NULLS (row-major)
mp__collect() {
    local d=${1:-data} k
    local -i r c n nc=${#MP_COLS[@]}
    mp_count "$d"; n=$REPLY
    for ((r = 0; r < n; r++)); do
        for ((c = 0; c < nc; c++)); do
            k=$d.$r.$c
            [[ -n ${MP_JSON[$k]+x} ]] || k=$d.$r.${MP_COLS[c]}
            if mp_get "$k"; then MP_CELLS+=("$REPLY") MP_NULLS+=(0); else MP_CELLS+=("") MP_NULLS+=(1); fi
        done
    done
}

mp__csv() {
    local s=$1
    if [[ $s == *[,\"$'\n\r']* ]]; then s=${s//\"/\"\"}; REPLY="\"$s\""; else REPLY=$s; fi
}

# Print MP_COLS / MP_CELLS as FORMAT (table|csv|vertical). $2=1 prints the header
# (csv) and $3 is the row number to start from (vertical).
mp__print_rows() {
    local fmt=$1 header=${2:-1} cell line dash
    local -i start=${3:-1} nc=${#MP_COLS[@]} nr i c x
    local -a w
    (( nc > 0 )) || return 0
    nr=$(( ${#MP_CELLS[@]} / nc ))
    case $fmt in
        csv)
            if (( header )); then
                line=
                for ((c = 0; c < nc; c++)); do
                    mp__csv "${MP_COLS[c]}"
                    (( c )) && line+=,
                    line+=$REPLY
                done
                printf '%s\n' "$line"
            fi
            for ((i = 0; i < nr; i++)); do
                line=
                for ((c = 0; c < nc; c++)); do
                    mp__csv "${MP_CELLS[i*nc+c]}"
                    (( c )) && line+=,
                    line+=$REPLY
                done
                printf '%s\n' "$line"
            done
            ;;
        vertical)
            x=0
            for ((c = 0; c < nc; c++)); do (( ${#MP_COLS[c]} > x )) && x=${#MP_COLS[c]}; done
            for ((i = 0; i < nr; i++)); do
                printf -- '-[ RECORD %d ]%s\n' $(( start + i )) "--------------------"
                for ((c = 0; c < nc; c++)); do
                    cell=${MP_CELLS[i*nc+c]}
                    (( MP_NULLS[i*nc+c] )) && cell=NULL
                    printf '%s%*s | %s\n' "${MP_COLS[c]}" $(( x - ${#MP_COLS[c]} )) '' "$cell"
                done
            done
            ;;
        *)  # table
            for ((c = 0; c < nc; c++)); do w[c]=${#MP_COLS[c]}; done
            for ((i = 0; i < nr * nc; i++)); do
                cell=${MP_CELLS[i]}
                if (( MP_NULLS[i] )); then cell=NULL
                elif [[ $cell == *[$'\n\r\t']* ]]; then cell=${cell//[$'\n\r\t']/ }
                fi
                MP_CELLS[i]=$cell
                c=$(( i % nc ))
                (( ${#cell} > w[c] )) && w[c]=${#cell}
            done
            line= dash=
            for ((c = 0; c < nc; c++)); do
                (( c )) && line+='|' dash+='+'
                printf -v cell ' %s%*s ' "${MP_COLS[c]}" $(( w[c] - ${#MP_COLS[c]} )) ''
                line+=$cell
                printf -v cell '%*s' $(( w[c] + 2 )) ''
                dash+=${cell// /-}
            done
            printf '%s\n%s\n' "$line" "$dash"
            for ((i = 0; i < nr; i++)); do
                line=
                for ((c = 0; c < nc; c++)); do
                    cell=${MP_CELLS[i*nc+c]}
                    (( c )) && line+='|'
                    if (( MP_NUMCOLS[c] )); then
                        printf -v cell ' %*s%s ' $(( w[c] - ${#cell} )) '' "$cell"
                    else
                        printf -v cell ' %s%*s ' "$cell" $(( w[c] - ${#cell} )) ''
                    fi
                    line+=$cell
                done
                printf '%s\n' "$line"
            done
            ;;
    esac
}

# Print the result rows of the last response as FORMAT (table|csv|vertical|json).
mp_print_result() {
    local fmt=${1:-table}
    if [[ $fmt == json ]]; then printf '%s\n' "$MP_RESPONSE"; return 0; fi
    MP_CELLS=() MP_NULLS=()
    mp__collect data
    mp__print_rows "$fmt" 1
}

# ---------------------------------------------------------------------------
# Command line interface
# ---------------------------------------------------------------------------

mp__usage() {
    cat <<EOF
mapepire.sh $MP_VERSION - a pure bash client for Mapepire (IBM i Db2)

Usage: mapepire.sh [OPTIONS] [SQL...]

Runs each SQL argument, then the statements given with -c/-f, in order. With no
statements, starts an interactive shell (or reads statements from stdin).

Server mode (TLS is always used; requires openssl):
  -H, --host HOST          server host                 (env MAPEPIRE_HOST)
  -p, --port PORT          server port, default 8076   (env MAPEPIRE_PORT)
  -u, --user USER          IBM i user profile          (env MAPEPIRE_USER)
  -P, --password PASS      password; prompted if unset (env MAPEPIRE_PASSWORD)
      --ca FILE            trust the certificate(s) in this PEM file
  -k, --insecure           do not verify the server certificate
      --print-cert         print the server's certificate (PEM) and exit

Single mode (no network; JSON over stdin/stdout of a --single server):
  -S, --single COMMAND     e.g. "/QOpenSys/pkgs/bin/mapepire --single" on IBM i,
                           or "ssh myibmi /QOpenSys/pkgs/bin/mapepire --single"

Connection:
      --props PROPS        JDBC properties, e.g. "naming=system;libraries=MYLIB"
      --technique T        tcp or cli
      --application NAME   application name for job tracking

Execution:
  -c, --cl COMMAND         run a CL command
  -f, --file FILE          run the statements in FILE ("-" for stdin)
      --param VALUE        parameter for "?" markers (repeatable)
      --params JSON        all parameters as a JSON array, e.g. '[1,"A01"]'
  -F, --format FMT         table (default), csv, vertical or json
  -r, --rows N             rows fetched per round trip (default 1000)
  -m, --max-rows N         stop after N rows
      --ping               check that the server and database are alive
      --server-version     show the server version
      --debug              trace protocol messages to stderr
  -V, --version            show version
  -h, --help               show this help

In files, stdin and the interactive shell, statements end with ";" at the end of a
line. Interactive commands: \\cl CMD, \\format FMT, \\rows N, \\ping, \\version,
\\job, \\help, \\quit.
EOF
}

mp__err() { printf 'mapepire: %s\n' "$*" >&2; }

# Globals used by the CLI
MP__FMT=table MP__MAX=0 MP__PARAMS=

# Run one SQL statement and print its results. Returns 1 on error.
mp__cli_sql() {
    if [[ -n $MP__PARAMS ]]; then
        mp_prepare_sql_execute "$1" "$MP__PARAMS"
    else
        mp_sql "$1"
    fi || { mp__err "$MP_ERROR"; return 1; }
    mp__cli_print_results "$MP_ID"
}

# Print the current response and any further blocks of cursor $1
mp__cli_print_results() {
    local cursor=$1 fmt=$MP__FMT header=1 rc=0
    local -i total=0 nc nr base
    if [[ ${MP_JSON[has_results]-} != true ]]; then
        if [[ $fmt == json ]]; then
            printf '%s\n' "$MP_RESPONSE"
        elif [[ $fmt != csv ]]; then
            mp_get update_count
            if (( ${REPLY:--1} == 1 )); then echo "1 row affected"
            elif (( ${REPLY:--1} >= 0 )); then echo "$REPLY rows affected"
            else echo OK
            fi
        fi
        return 0
    fi
    nc=${#MP_COLS[@]}
    MP_CELLS=() MP_NULLS=()
    while :; do
        if [[ $fmt == json ]]; then
            printf '%s\n' "$MP_RESPONSE"
            mp_count data; total+=REPLY
        else
            # table accumulates every block; the other formats stream each block
            base=0
            if [[ $fmt != table ]]; then MP_CELLS=() MP_NULLS=() base=total; fi
            mp__collect data
            nr=$(( nc ? ${#MP_CELLS[@]} / nc : 0 ))
            if (( MP__MAX > 0 && base + nr > MP__MAX )); then
                nr=$(( MP__MAX - base ))
                MP_CELLS=("${MP_CELLS[@]:0:nr*nc}") MP_NULLS=("${MP_NULLS[@]:0:nr*nc}")
            fi
            if [[ $fmt == table ]]; then
                total=nr
            else
                mp__print_rows "$fmt" "$header" $(( total + 1 ))
                header=0 total+=nr
            fi
        fi
        [[ ${MP_JSON[is_done]-true} == true ]] && break
        (( MP__MAX > 0 && total >= MP__MAX )) && break
        mp_sqlmore "$cursor" || { mp__err "$MP_ERROR"; rc=1; break; }
    done
    if [[ $fmt == table ]]; then
        mp__print_rows table
        if (( total == 1 )); then echo "(1 row)"; else echo "($total rows)"; fi
    fi
    if [[ $MP__KIND ]]; then mp_sqlclose "$cursor" >/dev/null 2>&1; fi
    return $rc
}

mp__cli_cl() {
    local rc=0
    mp_cl "$1" || rc=1
    if [[ -n ${MP_JSON[data.#]+x} && ${MP_JSON[data.#]} != 0 ]]; then
        if [[ $MP__FMT == json ]]; then printf '%s\n' "$MP_RESPONSE"; else mp_print_result "$MP__FMT"; fi
    elif (( rc == 0 )) && [[ $MP__FMT != csv ]]; then
        [[ $MP__FMT == json ]] && printf '%s\n' "$MP_RESPONSE" || echo OK
    fi
    (( rc )) && mp__err "$MP_ERROR"
    return $rc
}

# Handle an interactive/script meta command (line starting with "\"). Returns 2 to quit.
mp__cli_meta() {
    local cmd=${1%% *} arg=
    [[ $1 == *' '* ]] && arg=${1#* }
    case $cmd in
        '\q' | '\quit' | '\exit') return 2 ;;
        '\cl') mp__cli_cl "$arg" ;;
        '\format' | '\f')
            case $arg in
                table | csv | vertical | json) MP__FMT=$arg ;;
                *) mp__err "format must be table, csv, vertical or json"; return 1 ;;
            esac ;;
        '\rows') [[ $arg == +([0-9]) ]] && MP_ROWS=$arg || { mp__err "\\rows needs a number"; return 1; } ;;
        '\ping') mp_ping && { mp_get db_alive; echo "alive, db_alive=$REPLY"; } || { mp__err "$MP_ERROR"; return 1; } ;;
        '\version') mp_getversion && { mp_get version; printf 'server %s' "$REPLY"; mp_get build_date; echo " ($REPLY)"; } || { mp__err "$MP_ERROR"; return 1; } ;;
        '\job') mp_getdbjob && { mp_get job; echo "$REPLY"; } || { mp__err "$MP_ERROR"; return 1; } ;;
        '\help' | '\h' | '\?')
            cat <<'EOF'
Statements end with ";" at the end of a line. Commands:
  \cl COMMAND      run a CL command          \ping       check the connection
  \format FMT      table|csv|vertical|json   \version    server version
  \rows N          rows per fetch            \job        database job name
  \quit            exit
EOF
            ;;
        *) mp__err "unknown command: $cmd (try \\help)"; return 1 ;;
    esac
}

# Read statements from fd $1 (interactive if $2=1) and run them.
mp__cli_script() {
    local fd=$1 interactive=${2:-0} line buf= trimmed prompt histfile=${HOME:-.}/.mapepire_history
    local -i rc=0 r
    if (( interactive )); then
        echo "Connected to ${MP_SINGLE:+single-mode server}${MP_SINGLE:-$MP_HOST:$MP_PORT} as job $MP_JOB. Type \\help for help."
        set -o history 2>/dev/null
        HISTFILE=$histfile
        history -r "$histfile" 2>/dev/null
    fi
    while :; do
        if (( interactive )); then
            prompt='mapepire> '
            [[ -n $buf ]] && prompt='       -> '
            IFS= read -r -e -p "$prompt" line || { echo; break; }
            [[ -n $line ]] && history -s -- "$line"
        else
            IFS= read -r -u "$fd" line || { [[ -z $line ]] && break; }
        fi
        line=${line%$'\r'}
        trimmed=${line#"${line%%[![:space:]]*}"}
        trimmed=${trimmed%"${trimmed##*[![:space:]]}"}
        if [[ -z $buf ]]; then
            [[ -z $trimmed || $trimmed == --* ]] && continue
            if [[ $trimmed == \\* ]]; then
                mp__cli_meta "$trimmed"; r=$?
                (( r == 2 )) && break
                (( r )) && rc=1
                continue
            fi
            if (( interactive )) && [[ $trimmed == @(exit|quit) ]]; then break; fi
        fi
        buf+=${buf:+$'\n'}$line
        if [[ $trimmed == *';' ]]; then
            buf=${buf%"${buf##*[![:space:]]}"}
            mp__cli_sql "${buf%;}" || rc=1
            buf=
            mp__alive || { mp__err "${MP_ERROR:-disconnected}"; return 1; }
        fi
    done
    if [[ -n ${buf//[[:space:]]/} ]]; then mp__cli_sql "$buf" || rc=1; fi
    if (( interactive )); then history -w "$histfile" 2>/dev/null; fi
    return $rc
}

mp_print_cert() {
    local line on=0 found=0
    command -v openssl >/dev/null 2>&1 || mp__fail "openssl is required" || return 1
    while IFS= read -r line; do
        line=${line%$'\r'}
        [[ $line == '-----BEGIN CERTIFICATE-----' ]] && on=1
        (( on )) && printf '%s\n' "$line"
        if [[ $line == '-----END CERTIFICATE-----' ]] && (( on )); then found=1; break; fi
    done < <(openssl s_client -connect "$MP_HOST:$MP_PORT" -showcerts </dev/null 2>/dev/null)
    (( found )) || mp__fail "could not retrieve a certificate from $MP_HOST:$MP_PORT"
}

mp_main() {
    local -a actions=() params=()
    local print_cert=0 have_params=0 opt val tty fd
    local -i rc=0
    MP_HOST=${MAPEPIRE_HOST:-$MP_HOST} MP_PORT=${MAPEPIRE_PORT:-$MP_PORT}
    MP_USER=${MAPEPIRE_USER:-$MP_USER} MP_PASSWORD=${MAPEPIRE_PASSWORD:-$MP_PASSWORD}
    MP_CA=${MAPEPIRE_CA:-$MP_CA}

    while (( $# )); do
        opt=$1
        if [[ $opt == --*=* ]]; then
            set -- "${opt%%=*}" "${opt#*=}" "${@:2}"
            opt=$1
        fi
        case $opt in
            -H | --host | -p | --port | -u | --user | -P | --password | --ca | -S | --single | \
            --props | --technique | --application | -c | --cl | -f | --file | --param | --params | \
            -F | --format | -r | --rows | -m | --max-rows)
                (( $# >= 2 )) || { mp__err "option $opt needs a value"; return 2; }
                val=$2
                shift ;;
        esac
        case $opt in
            -H | --host) MP_HOST=$val ;;
            -p | --port) MP_PORT=$val ;;
            -u | --user) MP_USER=$val ;;
            -P | --password) MP_PASSWORD=$val ;;
            --ca) MP_CA=$val ;;
            -k | --insecure) MP_TLS_VERIFY=0 ;;
            -S | --single) MP_SINGLE=$val ;;
            --props) MP_PROPS=$val ;;
            --technique) MP_TECHNIQUE=$val ;;
            --application) MP_APPLICATION=$val ;;
            -c | --cl) actions+=("cl:$val") ;;
            -f | --file) actions+=("file:$val") ;;
            --param) params+=("$val") have_params=1 ;;
            --params) MP__PARAMS=$val ;;
            -F | --format) MP__FMT=$val ;;
            -r | --rows) MP_ROWS=$val ;;
            -m | --max-rows) MP__MAX=$val ;;
            --ping) actions+=("meta:\\ping") ;;
            --server-version) actions+=("meta:\\version") ;;
            --print-cert) print_cert=1 ;;
            --debug) MP_DEBUG=1 ;;
            -V | --version) echo "mapepire.sh $MP_VERSION"; return 0 ;;
            -h | --help) mp__usage; return 0 ;;
            --) shift; for val in "$@"; do actions+=("sql:$val"); done; break ;;
            -?*) mp__err "unknown option: $opt (see --help)"; return 2 ;;
            *) actions+=("sql:$opt") ;;
        esac
        shift
    done

    case $MP__FMT in table | csv | vertical | json) ;; *) mp__err "format must be table, csv, vertical or json"; return 2 ;; esac
    for val in "$MP_PORT" "${MP_ROWS:-0}" "$MP__MAX"; do
        [[ $val == +([0-9]) ]] || { mp__err "expected a number, got '$val'"; return 2; }
    done
    (( have_params )) && { mp_json_array "${params[@]}"; MP__PARAMS=$REPLY; }

    if [[ -z $MP_SINGLE ]]; then
        [[ -n $MP_HOST ]] || { mp__err "no host given (use --host, or --single for single mode)"; return 2; }
        if (( print_cert )); then mp_print_cert || { mp__err "$MP_ERROR"; return 1; }; return 0; fi
        [[ -n $MP_USER ]] || { mp__err "no user given (use --user)"; return 2; }
        if [[ -z $MP_PASSWORD ]] && { exec {tty}<>/dev/tty; } 2>/dev/null; then
            IFS= read -r -s -p "Password for $MP_USER@$MP_HOST: " -u "$tty" MP_PASSWORD 2>&"$tty"
            echo >&"$tty"
            exec {tty}>&-
        fi
        [[ -n $MP_PASSWORD ]] || { mp__err "no password given (use --password or MAPEPIRE_PASSWORD)"; return 2; }
    fi

    trap '' PIPE
    MP_TERSE=1
    mp_connect || { mp__err "$MP_ERROR"; return 1; }

    if (( ${#actions[@]} == 0 )); then
        if [[ -t 0 ]]; then actions=("repl:"); else actions=("file:-"); fi
    fi
    for opt in "${actions[@]}"; do
        val=${opt#*:}
        case $opt in
            sql:*) mp__cli_sql "$val" || rc=1 ;;
            cl:*) mp__cli_cl "$val" || rc=1 ;;
            meta:*) mp__cli_meta "$val" || rc=1 ;;
            repl:*) mp__cli_script 0 1 || rc=1 ;;
            file:-) mp__cli_script 0 || rc=1 ;;
            file:*)
                if [[ -r $val ]]; then
                    exec {fd}<"$val"
                    mp__cli_script "$fd" || rc=1
                    exec {fd}<&-
                else
                    mp__err "cannot read file: $val"; rc=1
                fi ;;
        esac
        mp__alive || { mp__err "${MP_ERROR:-disconnected}"; return 1; }
    done
    mp_close
    return $rc
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    mp_main "$@"
    exit $?
fi
