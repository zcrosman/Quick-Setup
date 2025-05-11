#!/bin/bash
#PATHS
agressor_path='/opt/BOFs'
powershell_scripts='/opt/powershell'
tools_path='/opt'
win_source='/opt/Windows/Source'
win_compiled='/opt/Windows/Compiled'
payload_mod='/opt/payloads'   

# Setup logging
LOG_DIR="$HOME"
LOG_FILE="install.log"
LOG_PATH="$LOG_DIR/$LOG_FILE"
rm -f "$LOG_PATH" && touch "$LOG_PATH"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_PATH"
}

log_message "Setting up logging to $LOG_PATH"
exec 3>&1 4>&2
trap 'exec 2>&4 1>&3' 0 1 2 3 RETURN
exec 1>$LOG_PATH 2>&1

# Status Indicators
GREENPLUS='\e[1;32m[+]\e[0m'
REDEXCLAIM='\e[1;31m[!!]\e[0m'
GOLDDASH='\e[1;33m[-]\e[0m'
BLUE='\033[34m'
LIGHT_BLUE_BOLD='\033[1;34m'
NOCOLOR='\033[0m'

# Logging Functions
log() {
    local message
    message=$(echo -e "$GREENPLUS $1")
    echo "$message" >&3  # Write to original stdout
    log_message "$message"
}

log_sub() {
    local message
    message=$(echo -e "   $GOLDDASH $1")
    echo "$message" >&3  # Write to original stdout
    log_message "$message"
}

log_error() {
    local message
    message=$(echo -e "$REDEXCLAIM $1")
    echo "$message" >&3  # Write to original stdout
    log_message "$message"
}

# check_user() {
# if [ "$EUID" -ne 0 ]
#     then echo -e "\nScript must be run with sudo\n"
#     echo -e "sudo -E ./setup.sh"
#     echo -e "sudo -E ./setup.sh 1 GITHUB_TOKEN"
#     exit
# fi
# }

# Check if running as zsh or bash
# if [[ $0 == *zsh ]]; then
#     echo "Running as zsh"
# elif [[ $0 == *bash ]]; then
#     echo "Running as bash"
# else
#     echo "Running under a different shell: $0"
#     echo "Run with bash instead: bash setup.sh 1"
#     exit
# fi

setup() {
    # Initial updates and installs
    log "Running initial setup"
    log_sub "Updating apt and installing base packages"
    sudo apt update
    sudo apt install -y git-all python3-pip pipx git golang
    
    log_sub "Upgrading pip"
    python3 -m pip install --upgrade pip
    
    log_sub "Setting permissions"
    sudo chown -R $USER:$USER /opt
    
    log_sub "Setting Screenshot Shortcut (ctrl+shift+s)"
    # From Bryan - set flameshort shortcut
    if [ "$XDG_CURRENT_DESKTOP" == "GNOME" ]; then
        gsettings set org.gnome.settings-daemon.plugins.media-keys custom-keybindings "['/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/']"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ name "'flameshot'"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ binding "'<primary><shift>s'"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ command "'flameshot gui'"
    else
        xfconf-query -c xfce4-keyboard-shortcuts -p "/commands/custom/<Primary><Shift>S" --create --type string --set "flameshot gui"
    fi
    log "Initial setup complete"
}

zsh_setup(){
    log "Setting up zsh"
    cd $tools_path/Quick-Setup
    log_sub "Downloading Oh My Zsh"
    wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O zsh-install.sh
    # patch to remove auto start zsh
    #sed '/exec zsh -l/d' zsh-install.sh
    chmod +x zsh-install.sh
    log_sub "Installing Oh My Zsh"
    echo "y" | ./zsh-install.sh

    log_sub "Customizing zsh configuration"
    sed -i 's/ZSH_THEME=\"robbyrussell\"/ZSH_THEME=\"zach\"/g' $HOME/.zshrc
    sed -i -e 's/plugins=(git)/plugins=( z zsh-autosuggestions zach-shortcuts zach-terminal-logger copyfile zsh-syntax-highlighting)/g' $HOME/.zshrc
    
    log_sub "Installing zsh plugins"
    # https://github.com/zsh-users/zsh-autosuggestions
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
    # QOL - Manually add to history long, command commands?
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting
    
    log_sub "Adding History for auto suggestions"
    cp ~/.zsh_history ~/.zsh_history.bak
    cat /opt/Quick-Setup/misc/fake_history ~/.zsh_history > ~/.zsh_history_tmp
    mv ~/.zsh_history_tmp ~/.zsh_history

    log_sub "Setting up additional plugins"
    git clone https://github.com/agkozak/zsh-z ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-z
    mkdir -p ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach-shortcuts
    if [ -f /opt/Quick-Setup/misc/zach-shortcuts.plugin.zsh ]; then
        cp /opt/Quick-Setup/misc/zach-shortcuts.plugin.zsh ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach-shortcuts/zach-shortcuts.plugin.zsh
    fi
    mkdir -p ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach-terminal-logger
    if [ -f /opt/Quick-Setup/misc/zach-terminal-logger.plugin.zsh ]; then
        cp /opt/Quick-Setup/misc/zach-terminal-logger.plugin.zsh ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach-terminal-logger/zach-terminal-logger.plugin.zsh
    fi

    log_sub "Installing custom theme"
    if [ -f /opt/Quick-Setup/misc/zach.zsh-theme ]; then
        cp /opt/Quick-Setup/misc/zach.zsh-theme ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/themes/zach.zsh-theme
    fi

    log_sub "Updating PATH in .zshrc"
    GOFIX="/usr/lib/go"; go version > /dev/null 2>&1 || GOFIX="/usr/local/go"; # because i swap between different images. checks which one is right
    echo "export GOROOT=$GOFIX" >> $HOME/.zshrc
    echo "export GOPATH=$HOME/go" >> $HOME/.zshrc
    echo "export PATH=$GOPATH/bin:$GOROOT/bin:/opt/scripts:$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH" >> $HOME/.zshrc

    log "zsh setup complete"
}

check_go(){
    log "Checking if Go is installed"
    which go 
    if [ $? -ne 0 ]
        then 
            log_sub "Go not found, installing..."
            install_go 
    else
        log_sub "Go already installed"
    fi
}

install_go(){
    log "Installing Go"
    sudo apt install -y golang 
    export GOROOT=/usr/local/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    log_sub "Go installation complete"
}

install_BOFs() {
    # Agressor Scripts Download
    log "Installing BOF agressor scripts in $agressor_path"
    mkdir $agressor_path
    ln -s $agressor_path ~/BOFs
    cp loader.cna $agressor_path/loader.cna
    
    log_sub "Cloning CS-Situational-Awareness"
    git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git $agressor_path/CS-Situational-Awareness 
    
    log_sub "Cloning CS-Remote-OPs-BOF"
    git clone https://github.com/trustedsec/CS-Remote-OPs-BOF.git $agressor_path/CS-Remote-OPs-BOF 
    
    log_sub "Cloning Rasta-agressor-scripts"
    git clone https://github.com/rasta-mouse/Aggressor-Script.git $agressor_path/Rasta-agressor-scripts 
    
    log_sub "Cloning Und3rf10w-agressor-scripts"
    git clone https://github.com/Und3rf10w/Aggressor-scripts.git $agressor_path/Und3rf10w-agressor-scripts 
    
    log_sub "Cloning harleyQu1nn-agressor-scripts"
    git clone https://github.com/harleyQu1nn/AggressorScripts $agressor_path/harleyQu1nn-agressor-scripts 
    
    log_sub "Cloning CredBandit"
    git clone https://github.com/anthemtotheego/CredBandit.git $agressor_path/CredBandit 
    
    log_sub "Cloning cobalt-arsenal"
    git clone https://github.com/mgeeky/cobalt-arsenal.git $agressor_path/cobalt-arsenal 
    
    log_sub "Cloning AceLdr"
    git clone https://github.com/kyleavery/AceLdr.git $agressor_path/AceLdr 
    
    log_sub "Cloning HelpColor"
    git clone https://github.com/outflanknl/HelpColor.git $agressor_path/HelpColor 
    
    log_sub "Cloning Flagvik-CobaltStuff"
    git clone https://github.com/Flangvik/CobaltStuff.git $agressor_path/Flagvik-CobaltStuff 
    
    log_sub "Cloning BokuLoader"
    git clone https://github.com/boku7/BokuLoader.git $agressor_path/BokuLoader 
    
    log_sub "Cloning SourcePoint"
    git clone https://github.com/Tylous/SourcePoint.git $agressor_path/SourcePoint 
    
    log_sub "Cloning nanodump"
    git clone https://github.com/helpsystems/nanodump.git $agressor_path/nanodump 
    
    log_sub "Cloning unhook"
    git clone https://github.com/rsmudge/unhook-bof $agressor_path/unhook 
    
    log_sub "Cloning RiccardoAncarani-BOFs"
    git clone https://github.com/RiccardoAncarani/BOFs.git $agressor_path/RiccardoAncarani-BOFs 
    
    log_sub "Cloning LdapSignCheck"
    git clone https://github.com/cube0x0/LdapSignCheck.git $agressor_path/LdapSignCheck
    
    log_sub "Cloning injectEtwBypass"
    git clone https://github.com/boku7/injectEtwBypass.git $agressor_path/injectEtwBypass
    
    log_sub "Cloning Detect-Hooks"
    git clone https://github.com/anthemtotheego/Detect-Hooks $agressor_path/Detect-Hooks  
    
    log_sub "Cloning tgtdelegation"
    git clone https://github.com/connormcgarr/tgtdelegation $agressor_path/tgtdelegation
    
    log_sub "Cloning cookie-monster"
    git clone https://github.com/KingOfTheNOPs/cookie-monster.git $agressor_path/cookie-monster
    cd $agressor_path/cookie-monster
    log_sub "Installing cookie-monster requirements"
    python3 -m pip install -r requirements.txt
    make
    
    log_sub "Cloning smbtakeover"
    git clone https://github.com/zyn3rgy/smbtakeover $agressor_path/smbtakeover
    
    log_sub "Cloning outflank-tool-collection"
    git clone https://github.com/outflanknl/C2-Tool-Collection.git $agressor_path/outflank-tool-collection
    cd $agressor_path/outflank-tool-collection/BOF
    log_sub "Building outflank tools"
    make all
    
    log_sub "Cloning ajpc500-bofs"
    git clone https://github.com/ajpc500/BOFs.git $agressor_path/ajpc500-bofs
    
    log_sub "Cloning rvrsh3ll-BOF_Collection"
    git clone https://github.com/rvrsh3ll/BOF_Collection $agressor_path/rvrsh3ll-BOF_Collection
    
    log_sub "Setting up BOFNET"
    wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb 
    rm packages-microsoft-prod.deb 
    sudo apt-get install -y apt-transport-https 
    sudo apt-get install -y dotnet-sdk-5.0 
    git clone https://github.com/williamknows/BOF.NET.git $agressor_path/BOFNET 
    mkdir $agressor_path/BOFNET/build 
    cd $agressor_path/BOFNET/build 
    sudo apt install -y cmake 
    cmake -DCMAKE_INSTALL_PREFIX=$PWD/install -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake .. 
    cmake --build . 
    cmake --install . 
    
    log "BOF installation complete"
}

fast () {
    log "Running fast installation"
    
    log_sub "Removing existing Burp (outdated)"
    # todo
    log_sub "Installing Burp Professional (latest)"
    # todo
    lob_sub "Downloading Burp extensions"
    # todo
    # nuclei-burp extension
    # auto install plugins in the app store?

    log_sub "Installing Sublime Text"
    wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null 
    echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list 
    sudo apt-get update 
    sudo apt-get -y install sublime-text 

    log_sub "Installing Kerbrute"
    go install github.com/ropnop/kerbrute@latest

    log_sub "Installing Aquatone"
    git clone https://github.com/michenriksen/aquatone.git $tools_path/aquatone 
    cd $tools_path/aquatone 
    ./build.sh 

    log_sub "Installing proxychains4 and libreoffice"
    apt install proxychains4 libreoffice -y

    log_sub "Installing Linux static binaries"
    git clone https://github.com/andrew-d/static-binaries.git $tools_path/linux-static-binaries 

    log_sub "Installing scrying"
    git clone https://github.com/nccgroup/scrying.git $tools_path/scrying 
    
    log_sub "Installing feroxbuster"
    sudo apt install -y feroxbuster 

    log_sub "Installing PetitPotam"
    git clone https://github.com/topotam/PetitPotam.git $tools_path/PetitPotam 

    log_sub "Installing coercer"
    python3 -m pip install coercer

    log_sub "Installing GoWitness"
    go install -v github.com/sensepost/gowitness@latest

    log_sub "Installing onedrive_user_enum"
    git clone https://github.com/nyxgeek/onedrive_user_enum $tools_path/onedrive_user_enum
    cd $tools_path/onedrive_user_enum
    python3 -m pip install -r requirements.txt

    log_sub "Installing Go365"
    go install https://github.com/optiv/Go365@latest

    log_sub "Installing TrevorSpray"
    pip install git+https://github.com/blacklanternsecurity/trevorproxy
    pip install git+https://github.com/blacklanternsecurity/trevorspray

    log_sub "Installing TeamFiltration"
    wget https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Linux-v3.5.0.zip -O $tools_path/TeamFiltration-Linux-v3.5.0.zip
    unzip TeamFiltration-Linux-v3.5.0.zip 
    
    # log_sub "Installing spraycharles"
    # python3 -m pip install pipx
    # python3 -m pipx ensurepath
    # python3 -m pipx install spraycharles

    log_sub "Installing nuclei"
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

    log_sub "Installing NTLMrecon"
    git clone https://github.com/pwnfoo/ntlmrecon $tools_path/ntlmrecon
    cd $tools_path/ntlmrecon
    python3 setup.py install

    log_sub "Installing bopscrk"
    python3 -m pip install bopscrk

    log_sub "Installing MailSniper"
    git clone https://github.com/dafthack/MailSniper.git $powershell_scripts/MailSniper 

    log_sub "Installing censys"
    python3 -m pip install censys

    log_sub "Installing waybackurls"
    go install github.com/tomnomnom/waybackurls@latest
    log_sub "Installing httprobe"
    go install github.com/tomnomnom/httprobe@latest
    log_sub "Installing assetfinder"
    go install github.com/tomnomnom/assetfinder@latest
    log_sub "Installing meg"
    go install github.com/tomnomnom/meg@latest
    log_sub "Installing gf"
    go install github.com/tomnomnom/gf@latest
    log_sub "Installing anew"
    go install github.com/tomnomnom/anew@latest
    log_sub "Installing gron"
    go install github.com/tomnomnom/gron@latest
    log_sub "Installing unfurl"
    go install github.com/tomnomnom/unfurl@latest
    log_sub "Installing fff"
    go install github.com/tomnomnom/fff@latest
    log_sub "Installing gau"
    go install github.com/lc/gau@latest
    log_sub "Removing existing httpx"

    which -a httpx > /tmp/abc235 && 
if [ -f $(which ls) ] ; then while read -r file; do rm "$file"; done < /tmp/abc235; fi; rm /tmp/abc235
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    log_sub "Installing unconver"
    go install github.com/projectdiscovery/uncover/cmd/uncover@latest
    log_sub "Installing dnsx"
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    log_sub "Installing alterx"
    go install github.com/projectdiscovery/alterx/cmd/alterx@latest
    log_sub "Installing mapcidr"
    go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
    log_sub "Installing s3scanner"
    git clone https://github.com/sa7mon/S3Scanner.git $tools_path/s3scanner
    cd $tools_path/s3scanner
    go build .

    log_sub "Installing gospider"
    GO111MODULE=on go install github.com/jaeles-project/gospider@latest

    log_sub "Installing Postman"
    mkdir $tools_path/Postman
    sudo apt install snapd -y
    systemctl start snapd
    snap install core
    snap install postman

    log_sub "Installing Amass"
    go install -v github.com/OWASP/Amass/v3/...@master  
    
    log "Fast installation complete"
}

install_tools() {
    log "Installing Kali tools"
    
    log_sub "Checking BloodHound"
    check_bh
    log_sub "Installing bofhound"
    pip3 install bofhound

    log_sub "Installing mitm6"
    git clone https://github.com/dirkjanm/mitm6.git $tools_path/mitm6 
    cd $tools_path/mitm6
    python3 setup.py install 

    log_sub "Installing Bloodhound.py"
    git clone https://github.com/fox-it/BloodHound.py.git $tools_path/BloodHound_NEW.py 

    log_sub "Installing PRET"
    pip install colorama pysnmp 
    pip install win_unicode_console 
    git clone https://github.com/RUB-NDS/PRET $tools_path/PRET 

    log_sub "Installing WebClientServiceScanner"
    git clone https://github.com/Hackndo/WebclientServiceScanner.git $tools_path/WebclientServiceScanner 
    cd $tools_path/WebclientServiceScanner
    python3 setup.py install 

    log_sub "Installing pypykatz"
    git clone https://github.com/skelsec/pypykatz.git $tools_path/pypykatz 

    log_sub "Installing DonPAPI"
    git clone https://github.com/login-securite/DonPAPI.git $tools_path/DonPAPI 
    python3 -m pip install -r $tools_path/DonPAPI/requirements.txt 

    log_sub "Installing ntlm_theft"
    git clone https://github.com/Greenwolf/ntlm_theft.git $tools_path/ntlm_theft

    log_sub "Installing ldapdomaindump"
    git clone https://github.com/dirkjanm/ldapdomaindump.git $tools_path/ldapdomaindump 
    cd $tools_path/ldapdomaindump 
    python3 setup.py install 

    log_sub "Installing DPAT"
    git clone https://github.com/clr2of8/DPAT.git $tools_path/DPAT 

    log_sub "Installing Certipy"
    git clone https://github.com/ly4k/Certipy.git $tools_path/Certipy
    cd $tools_path/Certipy
    python3 setup.py install

    log_sub "Installing firefox_decrypt"
    git clone https://github.com/unode/firefox_decrypt $tools_path/firefox_decrypt

    log_sub "Installing noPac"
    git clone https://github.com/Ridter/noPac.git $tools_path/noPac 
    cd $tools_path/noPac
    python3 -m pip install -r requirements.txt 

    log_sub "Installing Pcredz"
    git clone https://github.com/lgandx/PCredz.git $tools_path/Pcredz
    cd $tools_path/Pcredz
    docker build -t pcredz .

    log_sub "Installing flamingo"
    go install -v github.com/atredispartners/flamingo@latest

    log_sub "Installing arsenal"
    python3 -m pip install arsenal-cli

    log_sub "Installing MANSPIDER"
    git clone https://github.com/blacklanternsecurity/MANSPIDER $tools_path/MANSPIDER
    cd $tools_path/MANSPIDER
    python3 -m pip install -r requirements.txt
    python3 -m pip install textract
    sudo apt install -y tesseract-ocr antiword

    log_sub "Installing CrackHound"
    git clone https://github.com/trustedsec/CrackHound $tools_path/CrackHound
    cd $tools_path/CrackHound
    python3 -m pip install -r requirements.txt

    log_sub "Installing Plumhound"
    git clone https://github.com/PlumHound/PlumHound.git $tools_path/Plumhound
    cd $tools_path/Plumhound
    python3 -m pip install -r requirements.txt

    log_sub "Installing Max"
    git clone https://github.com/knavesec/Max.git $tools_path/Max
    cd $tools_path/Max
    python3 -m pip install -r requirements.txt

    log_sub "Installing PowerSploit"
    git clone https://github.com/PowerShellMafia/PowerSploit.git $powershell_scripts/PowerSploit 

    log_sub "Installing Nishang"
    git clone https://github.com/samratashok/nishang.git $powershell_scripts/ninshang 

    log_sub "Installing PrivescCheck"
    git clone https://github.com/itm4n/PrivescCheck.git $powershell_scripts/PrivescCheck 
    
    log_sub "Installing go-secdump (original)"
    go install github.com/jfjallid/go-secdump@latest

    log "Tool installation complete"
}

check_bh() {
    # check if bloodhound installed
    DIR=$tools_path'/BloodHound'
    log "Checking for BloodHound installation in $DIR"
    if [ -d $tools_path'/BloodHound' ]
    then
        log_sub "BloodHound Already Installed"
        log_sub "Copying custom queries to ~/.config/bloodhound/customqueries.json"
        cp $tools_path/Quick-Setup/customqueries.json ~/.config/bloodhound/customqueries.json 
        #start_bh
    else
        log_sub "BloodHound not installed"
        log_sub "Installing BloodHound and Neo4j"
        install_bh
        #start_bh
    fi
}

# Helper for user input prompts
prompt_user() {
    # Temporarily restore original stdout/stderr for interaction
    exec 1>&3 2>&4
    
    local prompt_text="$1"
    local response
    
    # Show the prompt and get input
    read -p "$prompt_text" response
    
    # Redirect back to log file
    exec 1>>$LOG_PATH 2>&1
    
    # Return the response
    echo "$response"
}

# Helper for password prompts
prompt_password() {
    # Temporarily restore original stdout/stderr for interaction
    exec 1>&3 2>&4
    
    local prompt_text="$1"
    local response
    
    # Show the prompt and get input without echo
    read -sp "$prompt_text" response
    echo "" >&3  # Add a newline after password entry
    
    # Redirect back to log file
    exec 1>>$LOG_PATH 2>&1
    
    # Return the response
    echo "$response"
}

# Update cme_config to use the prompt helpers
cme_config() {
    log "Configuring NetExec"
    nxc
    conf="$HOME/.nxc/nxc.conf"
    log_sub "Updating NetExec config in $conf"

    # For "professional" screenshots
    sed -i 's/Pwn3d/Admin Access/g' $conf
    sed -i 's/audit_mode =/audit_mode = */g' $conf
    sed -i 's/log_mode = False/log_mode = True/g' $conf

    # Update cme/bh integration
    log_sub "Configuring BloodHound integration"
    neo4j_usr=$(prompt_user "Neo4j Username: ")
    neo4j_pwd=$(prompt_password "Neo4j Password: ")
    
    log_sub "Setting BloodHound credentials in config"
    sed -i 's/bh_enabled = False/bh_enabled = True/g' $conf
    sed -i "s/bh_user = neo4j/bh_user = $neo4j_usr/g" $conf
    sed -i "s/bh_pass = neo4j/bh_pass = $neo4j_pwd/g" $conf
}

install_bh() {
    log "Installing BloodHound"
    # BloodHound
    mkdir $tools_path/BloodHound-All
    log_sub "Downloading BloodHound (Legacy)"
    wget https://github.com/BloodHoundAD/BloodHound/releases/download/rolling/BloodHound-linux-x64.zip -O $tools_path/BloodHound_legacy.zip     
    log_sub "Extracting BloodHound (Legacy)"
    cd $tools_path
    unzip BloodHound_legacy.zip  -d BloodHound_legacy


    # initialize cme to create cme.conf file
    # edit cme.conf to integrate with cme
    if [ -f '~/.nxc/nxc.conf' ]
    then
        log_sub "nxc.conf already exists"
        cme_config
    else
        log_sub "Initializing nxc"
        pipx install git+https://github.com/Pennyw0rth/NetExec
        cme_config
    fi

    log_sub "Adding custom Bloodhound queries"
    cp $tools_path/Quick-Setup/customqueries.json ~/.config/bloodhound/customqueries.json 

    # Neo4j
    log_sub "Configuring Neo4j"
    # Update to share with team
    sed -i -e '/#dbms.connectors.default_listen_address/s/^#//' /etc/neo4j/neo4j.conf
    # wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add - 
    # echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list 
    # apt-get update 
    # apt-get install -y apt-transport-https neo4j 
    systemctl restart neo4j 
    cp $tools_path/Quick-Setup/customqueries.json ~/.config/bloodhound/customqueries.json 
    
    log "BloodHound installation complete"
}

start_bh() {
    log "Starting BloodHound"
    cd $tools_path/BloodHound/BloodHound-linux-x64
    ./BloodHound --no-sandbox &
    
    log_sub "Starting Neo4j"
    cd /usr/bin
    sudo ./neo4j console 
    
    log_sub "Opening Neo4j interface in Firefox"
    runuser $(logname) -c "nohup firefox http://localhost:7474/browser/" &
}

win_source() {
    log "Installing Windows tools (source)"
    
    log_sub "Cloning Rubeus"
    git clone https://github.com/GhostPack/Rubeus.git $win_source/Rubeus 

    log_sub "Cloning Seatbelt"
    git clone https://github.com/GhostPack/Seatbelt.git $win_source/Seatbelt 

    log_sub "Cloning SharpUp"
    git clone https://github.com/GhostPack/SharpUp.git $win_source/SharpUpp 

    log_sub "Cloning SharPersist"
    git clone https://github.com/mandiant/SharPersist.git $win_source/SharPersist 

    log_sub "Cloning LaZagne"
    git clone https://github.com/AlessandroZ/LaZagne.git $win_source/lazagne 

    log "Windows source tools installation complete"
}

win_binaries(){
    log "Installing Windows binaries"

    log_sub "Downloading SharpShares"
    wget https://github.com/mitchmoser/SharpShares/releases/download/v2.4/SharpShares.exe -P $win_compiled

    log_sub "Downloading Snaffler"
    wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.96/Snaffler.exe -P $win_compiled

    log_sub "Downloading Group3r"
    wget https://github.com/Group3r/Group3r/releases/download/1.0.53/Group3r.exe -P $win_compiled

    log_sub "Downloading SharPersist"
    wget https://github.com/mandiant/SharPersist/releases/download/v1.0.1/SharPersist.exe -P $win_compiled

    log_sub "Downloading LaZagne"
    wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -P $win_compiled

    log_sub "Cloning GhostPack compiled binaries"
    git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git $win_compiled/GhostPack 

    log_sub "Downloading SharpHound (CE - latest)"
    wget https://github.com/SpecterOps/SharpHound/releases/download/v2.6.5/SharpHound_v2.6.5_windows_x86.zip -P $win_compiled
    cd $win_compiled
    unzip SharpHound_v2.6.5_windows_x86.zip

    log_sub "Downloading TeamFiltration"
    wget https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Win-v3.5.0.zip -P $win_compiled
    cd $win_compiled
    unzip TeamFiltration-Win-v3.5.0.zip 

    log_sub "Downloading SQL Server Management Studio"
    wget https://aka.ms/ssmsfullsetup -P $win_compiled

    copy2share
    
    log "Windows binaries installation complete"
}

# copy useful files to working drive
copy2share() {
    log_sub "Copying to shared working directory"
    if [ -d /share/Working ]
        then
        mkdir -p /share/Working/zach
        mkdir -p /share/Working/zach/WindowsBins
        cp -r $win_compiled /share/Working/zach/WindowsBins
    fi
}

install_wl() {
    log "Installing wordlists"
    sudo mkdir /usr/share/wordlists
    sudo chmod +w -R /usr/share/wordlists
    ln -s /usr/share/wordlists ~/wordlists
    cd /usr/share/wordlists
    
    log_sub "Extracting rockyou.txt"
    gzip -dq /usr/share/wordlists/rockyou.txt.gz 
    
    log_sub "Cloning statistically-likely-usernames"
    git clone https://github.com/insidetrust/statistically-likely-usernames.git /usr/share/wordlists/statistically-likely-usernames
    
    log_sub "Cloning SecLists"
    git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    
    log_sub "Cloning Bug-Bounty-Wordlists"
    git clone https://github.com/Karanxa/Bug-Bounty-Wordlists.git /usr/share/wordlists/Karanxa-Bug-Bounty
    
    log_sub "Cloning orwagodfather-fuzz-wl"
    git clone https://github.com/orwagodfather/WordList.git /usr/share/wordlists/orwagodfather-fuzz-wl
    
    log_sub "Cloning statistically-likely-usernames"
    git clone https://github.com/insidetrust/statistically-likely-usernames.git /usr/share/wordlists/statistically-likely-usernames
    
    log_sub "Cloning Default-Email-Repository-Project"
    git clone https://github.com/d1r7b46/Default-Email-Repository-Project /usr/share/wordlists/Default-Email-Repo-Project
    cd /usr/share/wordlists/Default-Email-Repo-Project/
    rm README.md x-disclaimer 
    cat * | sort -u -o combined.txt
    
    log "Wordlist installation complete"
}

payload_creation () {
    log "Setting up payload creation tools"
    mkdir $payload_mod
    
    log_sub "Installing PackMyPayload"
    git clone https://github.com/mgeeky/PackMyPayload.git $payload_mod/packmypayload 
    cd $payload_mod/packmypayload
    pip install --upgrade pip setuptools wheel 
    python3 -m pip install -r requirements.txt 

    #nimpact
    # TODO setup nim
    # git clone https://github.com/chvancooten/NimPackt-v1.git $tools_path/nimpact 
    # cd $tools_path/nimpactdocker
    # apt install -y nim 
    # pip3 install pycryptodome argparse 
    # nimble install -y winim nimcrypto 

    #nimcrypt
    # TODO setup nim
    
    # bankai
    log_sub "Installing bankai"
    git clone https://github.com/bigB0sss/bankai.git $payload_mod/bankai
    cd $payload_mod/bankai
    GO111MODULE=off go build bankai.go

    log_sub "Installing uru"
    git clone https://github.com/guervild/uru.git $payload_mod/uru 
    cd $payload_mod/uru
    go install mvdan.cc/garble@v0.8.0 
    go get github.com/C-Sto/BananaPhone 
    go install github.com/guervild/uru@latest 

    log_sub "Installing FuckThatPacker"
    git clone https://github.com/Unknow101/FuckThatPacker.git $payload_mod/ftp 

    log_sub "Installing AVSignSeek"
    git clone https://github.com/hegusung/AVSignSeek.git $payload_mod/AVSignSeek 

    log_sub "Installing darkarmour"
    git clone https://github.com/bats3c/darkarmour $payload_mod/darkarmour 
    sudo apt -y install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode 
    
    log_sub "Installing ScareCrow"
    git clone https://github.com/optiv/ScareCrow.git $payload_mod/ScareCrow 
    go get github.com/fatih/color 
    go get github.com/yeka/zip 
    go get github.com/josephspurrier/goversioninfo 
    sudo apt-get install -y openssl osslsigncode mingw-w64 
    go build $tools_path/ScareCrow/ScareCrow.go 
    
    log_sub "Installing donut-shellcode"
    pip install donut-shellcode 

    log_sub "Installing ruler"
    git clone https://github.com/sensepost/ruler.git $payload_mod/ruler 

    log_sub "Installing morphHTA"
    git clone https://github.com/vysecurity/morphHTA.git $payload_mod/morphHTA 

    log_sub "Installing Invoke-Obfuscation"
    git clone https://github.com/danielbohannon/Invoke-Obfuscation.git $payload_mod/Invoke-Obfuscation 

    log_sub "Installing mangle"
    git clone https://github.com/optiv/Mangle.git $payload_mod/mangle 
    cd $tools_path/mangle
    go get github.com/Binject/debug/pe 
    go install github.com/optiv/Mangle@latest 
 
    log_sub "Installing Freeze"
    git clone https://github.com/optiv/Freeze.git $payload_mod/Freeze 
    cd $tools_path/Freeze
    go build Freeze 

    log_sub "Installing Shhhloader"
    git clone https://github.com/icyguider/Shhhloader.git $payload_mod/Shhhloader
    cd $tools_path/Shhhloader
    python3 -m pip install -r requirements.txt
    
    log "Payload creation tools setup complete"
}

install_pythons () {
    log "Installing multiple Python versions"
    cd ~/Downloads
    
    log_sub "Installing Python 3.11.0"
    wget https://www.python.org/ftp/python/3.11.0/Python-3.11.0.tgz
    tar -xf Python-3.11.0.tgz
    cd Python-3.11.0
    ./configure --enable-optimizations
    make -j $(nproc)
    sudo make altinstall
    
    log_sub "Installing Python 3.9.0"
    cd ~/Downloads
    wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz
    tar -xf Python-3.9.0.tgz
    cd Python-3.9.0
    ./configure --enable-optimizations
    make -j $(nproc)
    sudo make altinstall
    
    log "Python installations complete"
}

# only for me :)
my_tools () {
    log "Installing personal tools"
    # Configure Git
    log_sub "Setting Git credential cache timeout (5 days)"
    git config --global credential.helper 'cache --timeout=432000'

    # Install public repositories first
    log_sub "Installing public repositories"
    
    log_sub "Cloning PassHound"
    git clone https://github.com/zcrosman/PassHound.git $tools_path/PassHound
    cd $tools_path/PassHound
    log_sub "Installing PassHound requirements"
    python3 -m pip install -r requirements.txt

    log_sub "Cloning git-emails"
    git clone https://github.com/zcrosman/git-emails.git $tools_path/git-emails

    # Prompt for GitHub token for private repositories
    log_sub "GitHub token required for private repositories"
    github_token=$(prompt_user "Enter your GitHub personal access token (press Enter to skip private repos): ")
    
    if [ -n "$github_token" ]; then
        # Store GitHub token temporarily
        log_sub "Storing GitHub credentials"
        echo "https://$github_token:x-oauth-basic@github.com" > ~/.git-credentials
        git config --global credential.helper 'store --file ~/.git-credentials'
        
        log_sub "Cloning private repositories"
        # Private
        mkdir -p ~/nuclei-custom
        
        log_sub "Cloning nuclei-custom"
        git clone https://zcrosman@github.com/zcrosman/nuclei-custom.git ~/nuclei-custom
        
        log_sub "Cloning random-scripts"
        git clone https://zcrosman@github.com/zcrosman/random-scripts.git $tools_path/scripts  
        chmod +x $tools_path/scripts/*
        
        log_sub "Cloning LockPick"
        git clone https://zcrosman@github.com/zcrosman/LockPick.git $tools_path/LockPick 
        
        log_sub "Cloning check-access"
        git clone https://zcrosman@github.com/zcrosman/check-access.git $tools_path/check-access 
        
        log_sub "Cloning go-secdump"
        git clone https://zcrosman@github.com/zcrosman/go-secdump.git $tools_path/go-secdump-custom
        
        log_sub "Cloning admi-assist"
        git clone https://zcrosman@github.com/zcrosman/admi-assist.git $tools_path/admi-assit
        
        log_sub "Cloning rtsp-peek"
        git clone https://zcrosman@github.com/zcrosman/rtsp-peek.git $tools_path/rtsp-peek
        
        log_sub "Cloning bnxc"
        git clone https://zcrosman@github.com/zcrosman/bnxc.git $tools_path/bnxc
        
        log_sub "Cloning bimpacket"
        git clone https://zcrosman@github.com/zcrosman/bimpacket.git $tools_path/bimpacket

        log_sub "Creating shared working directory"
        mkdir -p /share/Working/zach
        log_sub "Copying admi-assist to shared directory"
        cp -r /opt/admi-assit /share/Working/zach

        # Clean up credentials for security
        log_sub "Cleaning up GitHub credentials"
        rm -f ~/.git-credentials
        git config --global --unset credential.helper
        git config --global credential.helper 'cache --timeout=432000'
    else
        log_sub "Skipping private repositories"
    fi
    
    log "Personal tools installation complete"
}

menu () {
    # clear
    echo -e "\n    Select an option from menu:"                      
    echo -e "\n Key  Menu Option:               Description:"
    echo -e " ---  ------------               ------------"
    echo -e "  1 - Basic Install              Run commands (5,6,7)" 
    echo -e "  2 - Install All                Run all of the commands below (1-5)"    
    echo -e "  3 - Install Windows binaries   Install Windows binaries into " $win_compiled       
    echo -e "  4 - Install Windows source     Install Windows source into " $win_source                      
    echo -e "  5 - Install Linux tools        Install common Linux tools into " $tools_path
    echo -e "  6 - Instal BOFs                Install Cobalt Strike agressor scripts into " $agressor_path      
    echo -e "  7 - Payload Creation           Install tools for payload creation/modification into" $payload_mod                    
    echo -e "  8 - Start BloodHound           Start Neo4j and BloodHound (installs if not already installed)"
    echo -e "  f - FAST                       Essential tools for external assessment"
    echo -e "  w - Install wordlists          Install additional wordlists"
    echo -e "  p - Private tools              Install my private repos (requires Github token!):)"
    echo -e "  x - Exit                       Exit the setup script"                                      

    read -n1 -p "\n  Press key for menu item selection or press X to exit: " menu

    log_sub "User selected menu option: $menu"
    options $menu
}

options() {
    echo "Option $1 selected"
    if [ -n "$1" ]
        then
            case $1 in
                1) setup;check_go;install_BOFs;install_tools;fast;payload_creation;win_binaries;install_wl;my_tools;install_pythons;;
                2) setup;check_go;install_BOFs;install_tools;fast;payload_creation;win_binaries;win_source;install_wl;check_bh;my_tools;install_pythons;;
                3) win_binaries;;
                4) win_source;;
                5) setup;check_go;install_tools;;
                6) install_BOFs;;
                7) setup;check_go;payload_creation;;
                8) check_bh;;
                f) setup;fast;zsh_setup;install_wl;;
                g) check_go;;
                w) install_wl;;
                z) zsh_setup;;
                p) my_tools;;
                x) exit;;  
            esac
        else menu
    fi
}

# main
check_user 
options $1
