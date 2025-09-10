alias h='history -f'
alias hg='history -f | grep -i'
alias nocolor='sed "s/\x1B\[[0-9;]*[mGK]//g"'
alias ports='netstat -tulanp'
alias urlenc='python3 -c "import sys, urllib.parse as ul; print(ul.quote_plus(sys.argv[1]))"'
alias urldec='python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))"'
alias lower="tr '[:upper:]' '[:lower:]'"
alias upper="tr '[:lower:]' '[:upper:]'"
alias sortc="sort | uniq -c | sort -n"
alias calc='libreoffice --calc'
alias cutc='cut -d "," -f '
alias copy="xclip -r -selection clipboard"
alias which="which -a"
alias killburp="kill \$(ps -aux | grep burp | grep -v brows | grep -v grep | awk '{print \$2}')"
alias copylast="history --show-time="" | tail -1 | xclip -r -selection clipboard"
alias httpxl='httpx -p 80,81,300,443,591,593,832,981,1010,1311,2082,2087,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5800,6543,7000,7396,7474,8000,8001,8008,8014,8042,8069,8080,8081,8088,8090,8091,8118,8123,8172,8222,8243,8280,8281,8333,8443,8500,8834,8880,8888,8983,9000,9043,9060,9080,9090,9091,9200,9443,9800,9981,12443,16080,18091,18092,20720,28017'
alias ff="ffuf -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -rate 300 -e .txt,.zip,.xml,.json,.tar,.bak -t 100 -u"
alias iis="ffuf -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt -t 100 -rate 300 -e .aspx,.asp,.html,.htm,.ashx,.asmx,.txt,.zip,.bak,.svc,.xml,.rar,.json,.,/ -fl 4 -fw 17,73 -u"
alias jsp="ffuf -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt-t 100 -rate 300 -e .jsp,.do,.action,.txt,.zip,.bak,.html,.htm,.xml,.form -u"
alias php1="ffuf -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36' -c -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories-lowercase.txt-t 100 -rate 300 -e .php,.txt,.zip,.bak,.html,.htm,.xml -u"
if [[ "$OSTYPE" == "darwin"* ]]; then
    alias folder='open'
else
    alias folder='xdg-open'
fi
get-domains() {
  nxc smb "$1" | strings | grep -oP 'domain:\K[^\s)]+' | sort | uniq -c | sort -n
}
align_columns() {
    awk '
    {
        for (i = 1; i <= NF; i++) {
            if (length($i) > max_len[i]) {
                max_len[i] = length($i)
            }
            data[NR,i] = $i
        }
    }
    END {
        for (row = 1; row <= NR; row++) {
            for (col = 1; col <= NF; col++) {
                printf "%-*s ", max_len[col], data[row, col]
            }
            print ""
        }
    }
    ' "$@"
}
alias table='align_columns'
common() {
    comm -12 <(sort -u "$1") <(sort -u "$2")
}
ntlm_hash () {
    hash=$(iconv -f ASCII -t UTF-16LE <(printf "$1") | openssl dgst -md4 | cut -d" " -f2 )
    if [ -z "$2" ]; then
        file="/mnt/share/Working/loot/ntds.txt"
        if [ ! -f "$file" ]; then
            echo "Error: Static file $file does not exist."
            return 1
        fi
    else
        file="$2"
        if [ ! -f "$file" ]; then
            echo "Error: Specified file $file does not exist."
            return 1
        fi
    fi
    grep -i ${hash} "$file"
}
awkcol() {
    awk "{print \$$1}"
}
grepdir() {
    grep -rnw './' -e "$1"
}
extract() {
    if [ -f "$1" ]; then
        case "$1" in
            *.tar.bz2)   tar xvjf "$1"    ;;
            *.tar.gz)    tar xvzf "$1"    ;;
            *.bz2)       bunzip2 "$1"     ;;
            *.rar)       unrar x "$1"     ;;
            *.gz)        gunzip "$1"      ;;
            *.tar)       tar xvf "$1"     ;;
            *.tbz2)      tar xvjf "$1"    ;;
            *.tgz)       tar xvzf "$1"    ;;
            *.zip)       unzip "$1"       ;;
            *.Z)         uncompress "$1"  ;;
            *.7z)        7z x "$1"        ;;
            *)           echo "'$1' cannot be extracted via extract()" ;;
        esac
    else
        echo "'$1' is not a valid file"
    fi
}
serve() {
    local port="${1:-8000}"
    python -m http.server "$port"
    firefox "http://localhost:${port}/"
}
csize() {
    if [ -d "$1" ]; then
        du -sh "$1"
    elif [ -f "$1" ]; then
        du -h "$1"
    else
        echo "$1 is not a valid file or directory"
    fi
}
hist() {
    history | awk '{CMD[$2]++;count++;} END { for (a in CMD) print CMD[a] " " CMD[a]/count*100 "% " a; }' | grep -v "./" | column -c3 -s " " -t | sort -nr | nl | head -n10
}
sedreplace() {
    sed -i "" "s/$1/$2/g" $3
}
