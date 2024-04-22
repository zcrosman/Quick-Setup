alias h='history -f'
alias hg='history -f | grep -i'
alias nocolor='sed "s/\x1B\[[0-9;]*[mGK]//g"'
alias www='python3 -m http.server'
alias ports='netstat -tulanp'
alias urlenc='python3 -c "import sys, urllib as ul; print ul.quote_plus(sys.argv[1])"'
alias urldec='python3 -c "import sys, urllib as ul; print ul.unquote_plus(sys.argv[1])"'
alias lower="tr '[:upper:]' '[:lower:]'"
alias upper="tr '[:lower:]' '[:upper:]'"
alias sortc="sort | uniq -c | sort -n"
alias folder='xdg-open'
alias calc='libreoffice --calc'
alias cutc='cut -d "," -f'
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
    open "http://localhost:${port}/"
    python -m http.server "$port"
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