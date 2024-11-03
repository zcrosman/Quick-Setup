#PATHS
agressor_path='/opt/BOFs'
powershell_scripts='/opt/powershell'
tools_path='/opt'
win_source='/opt/Windows/Source'
win_compiled='/opt/Windows/Compiled'
payload_mod='/opt/payloads'   
debug=''
debug='1>/dev/null'


# check_user() {
# if [ "$EUID" -ne 0 ]
#     then echo -e "\nScript must be run with sudo\n"
#     echo -e "sudo -E ./setup.sh"
#     echo -e "sudo -E ./setup.sh 1 GITHUB_TOKEN"
#     exit
# fi
# }

setup() {
    # Initial updates and installs
    sudo apt update 
    sudo apt install -y git-all python3-pip pipx git
    sudo chown -R $USER:$USER /opt
    #zsh_setup
    # For docker
    # apt-get install wget
    # apt install zip -y
    echo "[*] Setting Screenshot Shortcut"

    # From Bryan - set flameshort shortcut
    if [ "$XDG_CURRENT_DESKTOP" == "GNOME" ]; then
        #gsettings get org.gnome.settings-daemon.plugins.media-keys custom-keybindings
        ## Set Shortcut
        gsettings set org.gnome.settings-daemon.plugins.media-keys custom-keybindings "['/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/']"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ name "'flameshot'"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ binding "'<primary><shift>s'"
        gsettings set org.gnome.settings-daemon.plugins.media-keys.custom-keybinding:/org/gnome/settings-daemon/plugins/media-keys/custom-keybindings/custom0/ command "'flameshot gui'"
    else
    ## XFCE
        xfconf-query -c xfce4-keyboard-shortcuts -p "/commands/custom/<Primary><Shift>S" --create --type string --set "flameshot gui"
    fi
}

zsh_setup(){
    cd ~
    wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O zsh-install.sh
    # patch to remove auto start zsh
    sed '/exec zsh -l/d' zsh-install.sh
    chmod +x zsh-install.sh
    echo "y" | ./zsh-install.sh

    
    sed -i 's/ZSH_THEME=\"robbyrussell\"/ZSH_THEME=\"jonathan\"/g' $HOME/.zshrc
    sed -i -e 's/plugins=(git)/plugins=( z zsh-autosuggestions zach copyfile )/g' $HOME/.zshrc
    # https://github.com/zsh-users/zsh-autosuggestions
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions
    # QOL - Manually add to history long, command commands?
    echo "Adding \"History\" for auto suggestions"
    cp ~/.zsh_history ~/.zsh_history.bak
    cat /opt/Quick-Setup/misc/fake_history ~/.zsh_history > ~/.zsh_history_tmp
    mv ~/.zsh_history_tmp ~/.zsh_history

    git clone https://github.com/agkozak/zsh-z ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-z
    mkdir ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach
    cp /opt/Quick-Setup/misc/zach.plugin.zsh ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zach/zach.plugin.zsh

    # https://github.com/ohmyzsh/ohmyzsh/tree/master/plugins/copybuffer - copy current command to clipboard (ctrl+o)
    
    # TODO - Finish testing
    # TODO - Update the plugins in ~/.zshrc
    # echo "export PATH=$PATH:/opt/scripts:$HOME/go/bin:$HOME/.local/bin:/usr/local/bin" >> $HOME/.zshrc
    echo "export GOROOT=/usr/lib/go" >> $HOME/.zshrc
    echo "export GOPATH=$HOME/go" >> $HOME/.zshrc
    echo "export PATH=$GOPATH/bin:$GOROOT/bin:/opt/scripts:$HOME/go/bin:$HOME/.local/bin:/usr/local/bin:$PATH" >> $HOME/.zshrc


    # exec zsh -l
}

check_go(){
    which go 
    if [ $? -ne 0 ]
        then install_go 
    else
        echo -e "\nGo already installed\n\n"
    fi
}

install_go(){
    echo "\n Installling Go\n"
    sudo apt install -y golang 
    export GOROOT=/usr/lib/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    # source ~/.bashrc
    source ~/.zshrc
}

install_BOFs() {
    # Agressor Scripts Download
    echo -e "\n\n\n Installing agressor scripts in " $agressor_path
    mkdir $agressor_path
    ln -s $agressor_path ~/BOFs
    cp loader.cna $agressor_path/loader.cna
    git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git $agressor_path/CS-Situational-Awareness 
    git clone https://github.com/trustedsec/CS-Remote-OPs-BOF.git $agressor_path/CS-Remote-OPs-BOF 
    git clone https://github.com/rasta-mouse/Aggressor-Script.git $agressor_path/Rasta-agressor-scripts 
    git clone https://github.com/Und3rf10w/Aggressor-scripts.git $agressor_path/Und3rf10w-agressor-scripts 
    git clone https://github.com/harleyQu1nn/AggressorScripts $agressor_path/harleyQu1nn-agressor-scripts 
    git clone https://github.com/anthemtotheego/CredBandit.git $agressor_path/CredBandit 
    git clone https://github.com/mgeeky/cobalt-arsenal.git $agressor_path/cobalt-arsenal 
    git clone https://github.com/kyleavery/AceLdr.git $agressor_path/AceLdr 
    git clone https://github.com/outflanknl/HelpColor.git $agressor_path/HelpColor 
    git clone https://github.com/Flangvik/CobaltStuff.git $agressor_path/Flagvik-CobaltStuff 
    git clone https://github.com/boku7/BokuLoader.git $agressor_path/BokuLoader 
    git clone https://github.com/Tylous/SourcePoint.git $agressor_path/SourcePoint 
    git clone https://github.com/helpsystems/nanodump.git $agressor_path/nanodump 
    git clone https://github.com/rsmudge/unhook-bof $agressor_path/unhook 
    git clone https://github.com/RiccardoAncarani/BOFs.git $agressor_path/RiccardoAncarani-BOFs 
    git clone https://github.com/cube0x0/LdapSignCheck.git $agressor_path/LdapSignCheck
    git clone https://github.com/boku7/injectEtwBypass.git $agressor_path/injectEtwBypass
    git clone https://github.com/anthemtotheego/Detect-Hooks $agressor_path/Detect-Hooks  
    git clone https://github.com/connormcgarr/tgtdelegation $agressor_path/tgtdelegation
    git clone https://github.com/KingOfTheNOPs/cookie-monster.git $agressor_path/cookie-monster
    cd $agressor_path/cookie-monster
    python3 -m pip install -r requirements.txt
    make
    git clone https://github.com/zyn3rgy/smbtakeover $agressor_path/smbtakeover
    #git clone https://github.com/DallasFR/Cobalt-Clip.git $agressor_path/Cobalt-clip
    git clone https://github.com/outflanknl/C2-Tool-Collection.git $agressor_path/outflank-tool-collection
    cd $agressor_path/outflank-tool-collection/BOF
    make all
    git clone https://github.com/ajpc500/BOFs.git $agressor_path/ajpc500-bofs
    # cd $agressor_path
    # ./setup.sh


    #todo build
    git clone https://github.com/rvrsh3ll/BOF_Collection $agressor_path/rvrsh3ll-BOF_Collection
    
    #BOFNET
    wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    sudo dpkg -i packages-microsoft-prod.deb 
    rm packages-microsoft-prod.deb 
    #apt-get update 
    sudo apt-get install -y apt-transport-https 
    #apt-get update 
    sudo apt-get install -y dotnet-sdk-5.0 
    git clone https://github.com/williamknows/BOF.NET.git $agressor_path/BOFNET 
    mkdir $agressor_path/BOFNET/build 
    cd $agressor_path/BOFNET/build 
    sudo apt install -y cmake 
    cmake -DCMAKE_INSTALL_PREFIX=$PWD/install -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake .. 
    cmake --build . 
    cmake --install . 

    # TODO add custom BOFs
}

fast () {
    #Submime
    wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null 
    echo "deb https://download.sublimetext.com/ apt/stable/" | sudo tee /etc/apt/sources.list.d/sublime-text.list 
    sudo apt-get update 
    sudo apt-get -y install sublime-text 

    # Kerbrute
    echo -e "Installing Kerbrute\n"
    go install github.com/ropnop/kerbrute@latest

    # Aquatone
    echo -e "Installing Aquatone\n"
    git clone https://github.com/michenriksen/aquatone.git $tools_path/aquatone 
    cd $tools_path/aquatone 
    ./build.sh 

    # static linux binaries (build as needed)
    # this version of the script does not build each binary
    echo -e "Installing Linux static binaries\n"
    git clone https://github.com/andrew-d/static-binaries.git $tools_path/linux-static-binaries 

    echo -e "Installing scrying\n"
    git clone https://github.com/nccgroup/scrying.git $tools_path/scrying 
    
    echo -e "Installing feroxbuster\n"
    sudo apt install -y feroxbuster 

    echo -e "Installing PetitPotam\n"
    git clone https://github.com/topotam/PetitPotam.git $tools_path/PetitPotam 

    echo -e "Installing coercer\n"
    python3 -m pip install coercer 

    # GoWitness
    go install -v github.com/sensepost/gowitness@latest

    git clone https://github.com/nyxgeek/onedrive_user_enum $tools_path/onedrive_user_enum
    cd $tools_path/onedrive_user_enum
    python3 -m pip install -r requirements.txt

    # Go365
    go install https://github.com/optiv/Go365@latest

    # TrevorSpray
    pip install git+https://github.com/blacklanternsecurity/trevorproxy
    pip install git+https://github.com/blacklanternsecurity/trevorspray

    wget https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Linux-v3.5.0.zip -O $tools_path/TeamFiltration-Linux-v3.5.0.zip
    unzip TeamFiltration-Linux-v3.5.0.zip 
    
    # spraycharles
    python3 -m pip install pipx
    python3 -m pipx ensurepath
    python3 -m pipx install spraycharles


    # nuclei
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

    #NTLMrecon
    git clone https://github.com/pwnfoo/ntlmrecon $tools_path/ntlmrecon
    cd $tools_path/ntlmrecon
    python3 seteup.py install

    # Wordlist Generation
    # git clone --recurse-submodules https://github.com/r3nt0n/bopscrk $tools_path/bobscrk
    # $tools_path/bobscrk
    # python3 -m pip install -r requirements.txt
    python3 -m pip install bopscrk

    # MailSniper
    echo -e "Installing MailSniper\n"
    git clone https://github.com/dafthack/MailSniper.git $powershell_scripts/MailSniper 

    python3 -m pip install censys

    # WEB Stuff
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/httprobe@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/tomnomnom/meg@latest
    go install github.com/tomnomnom/gf@latest
    go install github.com/tomnomnom/anew@latest
    go install github.com/tomnomnom/gron@latest
    go install github.com/tomnomnom/meg@latest
    go install github.com/tomnomnom/unfurl@latest
    go install github.com/tomnomnom/fff@latest
    go install github.com/lc/gau@latest
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install github.com/projectdiscovery/uncover/cmd/uncover@latest
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

    git clone https://github.com/sa7mon/S3Scanner.git $tools_path/s3scanner
    cd $tools_path/s3scanner
    go build .

    GO111MODULE=on go install github.com/jaeles-project/gospider@latest

    # Postman
    mkdir $tools_path/Postman
    sudo apt install snapd -y
    systemctl start snapd
    snap install core
    snap install postman

    echo -e "Installing Amass\n"
    go install -v github.com/OWASP/Amass/v3/...@master  

}

install_tools() {
    echo -e "\n\n\n Installing Kali tools\n\n\n"
    cme_config
    fast
    #BloodHound
    check_bh
    pip3 install bofhound

    # mitm6
    echo -e "Installing mitm6\n"
    git clone https://github.com/dirkjanm/mitm6.git $tools_path/mitm6 
    #pip3 install -r $tools_path/mitm6/requirements.txt 
    cd $tools_path/mitm6
    python3 setup.py install 

    # Bloodhound.py (Current Version)
    echo -e "Installing Bloodhound.py\n"
    git clone https://github.com/fox-it/BloodHound.py.git $tools_path/BloodHound_NEW.py 


    echo -e "Installing PRET\n"
    pip install colorama pysnmp 
    pip install win_unicode_console 
    git clone https://github.com/RUB-NDS/PRET $tools_path/PRET 

    echo -e "Installing WebClientServiceScanner\n"
    git clone https://github.com/Hackndo/WebclientServiceScanner.git $tools_path/WebclientServiceScanner 
    cd WebclientServiceScanner
    python3 setup.py install 

    # pypykatz
    echo -e "Installing pypykatz\n"
    git clone https://github.com/skelsec/pypykatz.git $tools_path/pypykatz 

    # evilwin-rm
    # gem install evil-winrm

    # DonPAPI
    echo -e "Installing DonPAPI\n"
    git clone https://github.com/login-securite/DonPAPI.git $tools_path/DonPAPI 
    python3 -m pip install -r $tools_path/DonPAPI/requirements.txt 

    # ntlm_theft
    git clone https://github.com/Greenwolf/ntlm_theft.git $tools_path/ntlm_theft

    echo -e "Installing ldapdomaindump\n"
    git clone https://github.com/dirkjanm/ldapdomaindump.git $tools_path/ldapdomaindump 
    cd $tools_path/ldapdomaindump 
    python3 setup.py install 

    echo -e "Installing DPAT\n"
    git clone https://github.com/clr2of8/DPAT.git $tools_path/DPAT 



    echo -e "Installing Certipy\n"
    git clone https://github.com/ly4k/Certipy.git $tools_path/Certipy
    cd $tools_path/Certipy
    python3 setup.py install

    git clone https://github.com/unode/firefox_decrypt $tools_path/firefox_decrypt

    echo -e "Installing noPac\n"
    git clone https://github.com/Ridter/noPac.git $tools_path/noPac 
    cd $tools_path/noPac
    python3 -m pip install -r requirements.txt 

    # echo -e "Install Pcredz"
    git clone https://github.com/lgandx/PCredz.git $tools_path/Pcredz
    cd $tools_path/Pcredz
    docker build -t pcredz .

    # flamingo
    go install -v github.com/atredispartners/flamingo@latest

    # CME for docker backup
    # git clone https://github.com/Porchetta-Industries/CrackMapExec.git $tools_path/CrackMapExec
    # cd $tools_path/CrackMapExec
    # docker build -t CrackMapExec .

    # arsenal
    python3 -m pip install arsenal-cli

    # pipx install git+https://github.com/blacklanternsecurity/MANSPIDER
    git clone https://github.com/blacklanternsecurity/MANSPIDER $tools_path/MANSPIDER
    cd $tools_path/MANSPIDER
    python3 -m pip install -r requirements.txt
    python3 -m pip install textract
    sudo apt install -y tesseract-ocr antiword


    # CrackHound
    git clone https://github.com/trustedsec/CrackHound $tools_path/CrackHound
    cd $tools_path/CrackHound
    python3 -m pip install -r requirements.txt

    # Plumhound
    git clone https://github.com/PlumHound/PlumHound.git $tools_path/Plumhound
    cd $tools_path/Plumhound
    python3 -m pip install -r requirements.txt

    # Max
    git clone https://github.com/knavesec/Max.git $tools_path/Max
    cd $tools_path/Max
    python3 -m pip install -r requirements.txt

    # Powershell Tools
    #PowerSploit (PowerView, PowerUp, etc)
    echo -e "Installing PowerSploit\n"
    git clone https://github.com/PowerShellMafia/PowerSploit.git $powershell_scripts/PowerSploit 

    # Nishang
    echo -e "Installing Nishang\n"
    git clone https://github.com/samratashok/nishang.git $powershell_scripts/ninshang 

    # PrivescCheck
    echo -e "Installing PrivescCheck\n"
    git clone https://github.com/itm4n/PrivescCheck.git $powershell_scripts/PrivescCheck 

}

check_bh() {
    # check if bloodhound installed
    DIR=$tools_path'/BloodHound'
    echo $DIR
    if [ -d $tools_path'/BloodHound' ]
    then
        echo -e "BloodHound Already Installed...."
        cp $tools_path/Quick-Setup/customqueries.json ~/.config/bloodhound/customqueries.json 
        #start_bh
    else
        echo -e "BloodHound not installed"
        echo -e "Installing BloodHound and Neo4j"
        install_bh
        #start_bh
    fi
}


cme_config() {

    conf="$HOME/.nxc/nxc.conf"
    echo "Updating NetExec config in "$conf

    # For "professional" screenshots
    sed -i 's/Pwn3d/Admin Access/g' $conf
    sed -i 's/audit_mode =/audit_mode = */g' $conf
    sed -i 's/log_mode = False/log_mode = True/g' $conf

    # Update cme/bh integration
    echo ''
    read -p "Neo4j Username: " neo4j_usr
    read -sp "Neo4j Password: " neo4j_pwd
    echo ''
    sed -i 's/bh_enabled = False/bh_enabled = True/g' $conf
    sed -i 's/bh_user = neo4j/bh_user = '$neo4j_usr'/g' $conf
    sed -i 's/bh_pass = neo4j/bh_pass = '$neo4j_pwd'/g' $conf
}




install_bh() {
    # BloodHound
    mkdir $tools_path/BloodHound-All
    wget https://github.com/BloodHoundAD/BloodHound/releases/download/rolling/BloodHound-linux-x64.zip -O $tools_path/BloodHound-All/BloodHound_current.zip 
    wget https://github.com/BloodHoundAD/BloodHound/releases/download/4.0.3/BloodHound-linux-x64.zip -O $tools_path/BloodHound-All/BloodHound_4.0.3.zip 
    cd $tools_path/BloodHound-All
    unzip BloodHound_current.zip -d BloodHound_current
    unzip BloodHound_4.0.3.zip -d BloodHound_old

    # initialize cme to create cme.conf file
    # edit cme.conf to integrate with cme
    if [ -d '~/.nxc/nxc.conf' ]
    then
        echo -e "nxc.conf already exists...."
        cme_config
    else
        echo -e "Initializing nxc"
        pipx install git+https://github.com/Pennyw0rth/NetExec
        nxc
        cme_config
    fi

    echo 'Adding custom Bloodhound queries (Hausec + CrackHound + custom)'
    cp $tools_path/Quick-Setup/customqueries.json ~/.config/bloodhound/customqueries.json 


    # Neo4j
    # Update to share with team
    sed -i -e '/#dbms.connectors.default_listen_address/s/^#//' /etc/neo4j/neo4j.conf
    # wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add - 
    # echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list 
    # apt-get update 
    # apt-get install -y apt-transport-https neo4j 
    systemctl restart neo4j 
}


start_bh() {
    echo -e "Starting BloodHound!!!"
    cd $tools_path/BloodHound/BloodHound-linux-x64
    ./BloodHound --no-sandbox &
    
    echo -e "Starting neo4j!!!"
    cd /usr/bin
    sudo ./neo4j console 
    echo -e "Starting neo4j interface (firefox)!!!"
    runuser $(logname) -c "nohup firefox http://localhost:7474/browser/" &
}


win_source() {
    echo -e "\n\n\n Installing Windows tools (source)\n\n\n"
    # Rubeus
    git clone https://github.com/GhostPack/Rubeus.git $win_source/Rubeus 

    # Seatbelt
    git clone https://github.com/GhostPack/Seatbelt.git $win_source/Seatbelt 

    # SharpUp
    git clone https://github.com/GhostPack/SharpUp.git $win_source/SharpUpp 

    # SharPersist
    git clone https://github.com/mandiant/SharPersist.git $win_source/SharPersist 

    # LaZagne
    git clone https://github.com/AlessandroZ/LaZagne.git $win_source/lazagne 


}

win_binaries(){
    echo -e "\n\n\n Installing Windows binaries\n\n\n"

    # SharpShares
    wget https://github.com/mitchmoser/SharpShares/releases/download/v2.4/SharpShares.exe -P $win_compiled

    # Snaffler
    wget https://github.com/SnaffCon/Snaffler/releases/download/1.0.96/Snaffler.exe -P $win_compiled

    # Group3r
    wget https://github.com/Group3r/Group3r/releases/download/1.0.53/Group3r.exe -P $win_compiled

    # SharPersist
    wget https://github.com/mandiant/SharPersist/releases/download/v1.0.1/SharPersist.exe -P $win_compiled


    # LaZagne
    wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -P $win_compiled

    # GhostPack Compiled
    git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git $win_compiled/GhostPack 

    # SharpHound
    wget https://github.com/BloodHoundAD/SharpHound/releases/download/v1.0.3/SharpHound-v1.0.3.zip -P $win_compiled
    cd $win_compiled
    unzip SharpHound-v1.0.3.zip

    # TeamFiltration
    wget https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Win-v3.5.0.zip  -P $win_compiled
    cd $win_compiled
    unzip TeamFiltration-Win-v3.5.0.zip 

    # SQL Server Management Studio (SSMS)
    wget https://aka.ms/ssmsfullsetup -P $win_compiled

}

install_wl() {
    sudo mkdir /usr/share/wordlists
    sudo chmod +w -R /usr/share/wordlists
    ln -s /usr/share/wordlists ~/wordlists
    cd /usr/share/wordlists
    gzip -dq /usr/share/wordlists/rockyou.txt.gz 
    # Add additional wordlists
    git clone https://github.com/insidetrust/statistically-likely-usernames.git /usr/share/wordlists/statistically-likely-usernames
    git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists
    git clone https://github.com/Karanxa/Bug-Bounty-Wordlists.git /usr/share/wordlists/Karanxa-Bug-Bounty
    git clone https://github.com/orwagodfather/WordList.git /usr/share/wordlists/orwagodfather-fuzz-wl
    git clone https://github.com/insidetrust/statistically-likely-usernames.git /usr/share/wordlists/statistically-likely-usernames
    git clone https://github.com/d1r7b46/Default-Email-Repository-Project /usr/share/wordlists/Default-Email-Repo-Project
}


payload_creation () {
    mkdir $payload_mod
    #packmypayload
    echo -e "Installing PackMyPayload\n"
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
    git clone https://github.com/bigB0sss/bankai.git $payload_mod/bankai
    cd $payload_mod/bankai
    GO111MODULE=off go build bankai.go

    #uru
    git clone https://github.com/guervild/uru.git $payload_mod/uru 
    cd $payload_mod/uru
    go install mvdan.cc/garble@v0.8.0 
    go get github.com/C-Sto/BananaPhone 
    go install github.com/guervild/uru@latest 

    #ftp
    git clone https://github.com/Unknow101/FuckThatPacker.git $payload_mod/ftp 

    # AVSignSeek (not payload creation, but used to detect where binary/paload is triggered in AV)
    git clone https://github.com/hegusung/AVSignSeek.git $payload_mod/AVSignSeek 

    # darkarmour
    git clone https://github.com/bats3c/darkarmour $payload_mod/darkarmour 
    sudo apt -y install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode 
    
    # ScareCrow
    git clone https://github.com/optiv/ScareCrow.git $payload_mod/ScareCrow 
    go get github.com/fatih/color 
    go get github.com/yeka/zip 
    go get github.com/josephspurrier/goversioninfo 
    sudo apt-get install -y openssl osslsigncode mingw-w64 
    go build $tools_path/ScareCrow/ScareCrow.go 
    
    # Donut
    pip3 install donut-shellcode 

    # Ruler
    git clone https://github.com/sensepost/ruler.git $payload_mod/ruler 

    #Morph-HTA
    git clone https://github.com/vysecurity/morphHTA.git $payload_mod/morphHTA 

    # Invoke-Obfuscation
    git clone https://github.com/danielbohannon/Invoke-Obfuscation.git $payload_mod/Invoke-Obfuscation 

    #mangle
    git clone https://github.com/optiv/Mangle.git $payload_mod/mangle 
    cd $tools_path/mangle
    go get github.com/Binject/debug/pe 
    go install github.com/optiv/Mangle@latest 
 
    # Freeze
    git clone https://github.com/optiv/Freeze.git $payload_mod/Freeze 
    cd $tools_path/Freeze
    go build Freeze 

    # Shhhloader
    git clone https://github.com/icyguider/Shhhloader.git $payload_mod/Shhhloader
    cd $tools_path/Shhhloader
    python3 -m pip install -r requirements.txt

    # ADMI
    # git clone https://github.com/zcrosman/ADMI.git $payload_mod/ADMI

}

# only for me :)
my_tools () {
    # 5 days
    git config --global credential.helper 'cache --timeout=432000'
    
    mkdir -p ~/nuclei-custom
    git clone https://zcrosman@github.com/zcrosman/nuclei-custom.git ~/nuclei-custom
    git clone https://zcrosman@github.com/zcrosman/random-scripts.git /opt/scripts  
    chmod +x /opt/scripts *
    git clone https://zcrosman@github.com/zcrosman/LockPick.git /opt/LockPick 
    git clone https://zcrosman@github.com/zcrosman/check-access.git /opt/check-access 

    # Passhound (public)
    git clone https://github.com/zcrosman/PassHound.git $tools_path/PassHound
    cd $tools_path/PassHound
    python3 -m pip install -r requirements.txt


  

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

    options $menu

    #rerun menu?
}

options() {
    echo "Option $1 selected"
    if [ -n "$1" ]
        then
            case $1 in
                1) setup;check_go;install_BOFs;install_tools;payload_creation;win_binaries;install_wl;my_tools;;
                2) setup;check_go;install_BOFs;install_tools;payload_creation;win_binaries;win_source;install_wl;check_bh;my_tools;;
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
