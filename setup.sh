#!/usr/bin/env bash

# TODO
# - testing
# - more tools!
# - automation of common repeatable tasks???


typeset -A bh_config
# If you want to use bloodhound integration with cme update the parameters below 
# If you want to remove this funcationality set the [bh_enabled] parameter to false
bh_config=(
    [bh_enabled]="True"
    [bh_uri]="127.0.0.1"
    [bh_port]="7687"
    [bh_user]="neo4j"       # CHANGE THIS
    [bh_pass]="password"    # CHANGE THIS
)


#PATHS
agressor_path='/home/'$SUDO_USER'/Documents/BOFs'
powershell_scripts='/opt/powershell'
tools_path='/opt'
win_source='/home/'$SUDO_USER'/Documents/Windows/Source'
win_compiled='/home/'$SUDO_USER'/Documents/Windows/Compiled'
payload_mod = '/opt'   


check_user() {
if [ "$EUID" -ne 0 ]
    then echo -e "\nScript must be run with sudo\n"
    echo -e "sudo ./setup.sh"
    exit
fi
}

setup() {
    # Initial updates and installs
    apt update
    apt install -y python3-pip
}

install_go(){
    sudo apt install -y golang
    export GOROOT=/usr/lib/go
    export GOPATH=$HOME/go
    export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
    source .bashrc
}

install_BOFs() {
    # Agressor Scripts Download
    echo -e "\n\n\n Installing agressor scripts\n\n\n"
    git clone https://github.com/trustedsec/CS-Situational-Awareness-BOF.git $agressor_path/CS-Situational-Awareness
    git clone https://github.com/trustedsec/CS-Remote-OPs-BOF.git $agressor_path/CS-Remote-OPs-BOF
    git clone https://github.com/rasta-mouse/Aggressor-Script.git $agressor_path/Rasta-agressor-scripts
    git clone https://github.com/Und3rf10w/Aggressor-scripts.git $agressor_path/Und3rf10w-agressor-scripts
    git clone https://github.com/harleyQu1nn/AggressorScripts $agressor_path/harleyQu1nn-agressor-scripts
    git clone https://github.com/anthemtotheego/CredBandit.git $agressor_path/CredBandit
    git clone https://github.com/mgeeky/cobalt-arsenal.git $agressor_path/cobalt-arsenal
    git clone https://github.com/boku7/BokuLoader.git $agressor_path/BokuLoader
    git clone https://github.com/kyleavery/AceLdr.git $agressor_path/AceLdr
    git clone https://github.com/outflanknl/HelpColor.git $agressor_path/HelpColor



    cd $agressor_path/BokuLoader
    make
    git clone https://github.com/Tylous/SourcePoint.git $agressor_path/SourcePoint
    git clone https://github.com/helpsystems/nanodump.git $agressor_path/nanodump
    git clone https://github.com/rsmudge/unhook-bof $agressor_path/unhook
    #BOFNET
    wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
    dpkg -i packages-microsoft-prod.deb
    rm packages-microsoft-prod.deb
    apt-get update
    apt-get install -y apt-transport-https
    apt-get update
    apt-get install -y dotnet-sdk-5.0
    git clone https://github.com/williamknows/BOF.NET.git $agressor_path/BOFNET
    mkdir BOFNET/build
    cd BOFNET/build
    sudo apt install -y cmake
    cmake -DCMAKE_INSTALL_PREFIX=$PWD/install -DCMAKE_BUILD_TYPE=MinSizeRel -DCMAKE_TOOLCHAIN_FILE=../toolchain/Linux-mingw64.cmake ..
    cmake --build .
    cmake --install .

    # TODO add custom BOFs
    # TODO load into Cobalt Strike
}

install_tools() {
    echo -e "\n\n\n Installing Kali tools\n\n\n"
    #Submime
    #wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | sudo apt-key add -
    wget -qO - https://download.sublimetext.com/sublimehq-pub.gpg | gpg --dearmor | tee /etc/apt/trusted.gpg.d/sublimehq-archive.gpg > /dev/null
    echo "deb https://download.sublimetext.com/ apt/stable/" | tee /etc/apt/sources.list.d/sublime-text.list
    #apt-get -y install apt-transport-https
    apt-get update
    apt-get -y install sublime-text

    # mitm6
    git clone https://github.com/dirkjanm/mitm6.git $tools_path/mitm6
    pip3 install -r $tools_path/mitm6/requirements.txt
    python $tools_path/mitm6/setup.py install

    # Bloodhound.py (Current Version)
    git clone https://github.com/fox-it/BloodHound.py.git $tools_path/BloodHound_NEW.py

    #Amass
    go install -v github.com/OWASP/Amass/v3/...@master


    pip install colorama pysnmp
    pip install win_unicode_console
    git clone https://github.com/RUB-NDS/PRET

    git clone https://github.com/Hackndo/WebclientServiceScanner.git $tools_path/WebclientServiceScanner
    cd WebclientServiceScanner
    python3 setup.py instdall

    # PEASS
    # TODO - add PEASS binaries to binaries folder
    git clone https://github.com/carlospolop/PEASS-ng.git $tools_path/PEASS

    # Kerbrute
    go get github.com/ropnop/kerbrute #TODO output dir

    # pypykatz
    git clone https://github.com/skelsec/pypykatz.git $tools_path/pypykatz

    # evilwin-rm
    gem install evil-winrm

    # DonPAPI
    https://github.com/login-securite/DonPAPI.git $tools_path/DonPAPI
    python3 -m pip install $tools_path/DonPAPI/requirements.txt
    
    # Eyewitness
    git clone https://github.com/FortyNorthSecurity/EyeWitness.git $tools_path/EyeWitness
    cd $tools_path/EyeWitness/Python/setup
    ./setup.sh

    # Aquatone
    git clone https://github.com/michenriksen/aquatone.git $tools_path/aquatone
    cd $tools_path/aquatone
    ./build.sh

    # static linux binaries (build as needed)
    # this version of the script does not build each binary
    git clone https://github.com/andrew-d/static-binaries.git $tools_path/linux-static-binaries

    git clone https://github.com/nccgroup/scrying.git $tools_path/scrying
    
    apt install -y feroxbuster
    
    git clone https://github.com/dirkjanm/ldapdomaindump.git $tools_path/ldapdomaindump
    cd $tools_path/ldapdomaindump
    python3 setup.py install

    git clone https://github.com/clr2of8/DPAT.git $tools_path/DPAT


    git clone https://github.com/topotam/PetitPotam.git $tools_path/PetitPotam


    python3 -m pip install coercer

    #git clone https://github.com/unode/firefox_decrypt $tools_path/firefox_decrypt

    git clone https://github.com/Ridter/noPac.git $tools_path/noPac
    cd $tools_path/noPac
    python3 -m pip install -r reaquirements.txt
    

    # Bloodhound and Neo4j install
    #install_bh




# Powershell Tools
    #PowerSploit (PowerView, PowerUp, etc)
    git clone https://github.com/PowerShellMafia/PowerSploit.git $powershell_scripts/PowerSploit

    # MailSniper
    git clone https://github.com/dafthack/MailSniper.git $powershell_scripts/MailSniper

    # Nishang
    git clone https://github.com/samratashok/nishang.git $powershell_scripts/ninshang

    # PrivescCheck
    git clone https://github.com/itm4n/PrivescCheck.git $powershell/PrivescCheck
}

check_bh() {
    DIR=$tools_path'/BloodHound'
    echo $DIR
    if [ -d $tools_path'/BloodHound' ]
    then
        echo -e "BloodHound Already Installed...."
        start_bh
    else
        echo -e "BloodHound not installed"
        echo -e "Installing BloodHound and Neo4j"
        install_bh
        start_bh
    fi

}


cme_config() {
    echo 'Setting up cme.conf'
    conf='/home/'$SUDO_USER'/.cme/cme.conf'

    # For "professional" screenshots
    sed -i 's/Pwn3d/Admin Access!/g' $conf

    # Update cme/bh integration
    sed -i 's/False/'${bh_config[bh_enabled]}'/g' $conf
    sed -i 's/127.0.0.1/'${bh_config[bh_uri]}'/g' $conf
    sed -i 's/7687/'${bh_config[bh_port]}'/g' $conf
    sed -i 's/user/'${bh_config[bh_user]}'/g' $conf
    sed -i 's/pass/'${bh_config[bh_pass]}'/g' $conf
}


install_bh() {
    # BloodHound
    mkdir $tools_path/BloodHound
    wget https://github.com/BloodHoundAD/BloodHound/releases/download/rolling/BloodHound-linux-x64.zip -O $tools_path/BloodHound/BloodHound_4.1.zip
    wget https://github.com/BloodHoundAD/BloodHound/releases/tag/4.0.3 -O $tools_path/BloodHound/BloodHound_4.0.3.zip
    cd $tools_path/BloodHound
    unzip BloodHound_4.1.zip
    unzip BloodHound_4.0.3.zip

    # initialize cme to create cme.conf file
    # edit cme.conf to integrate with cme
    if [ -d '/home/'$SUDO_USER'/.cme/cme.conf' ]
    then
        echo -e "cme.conf already exists...."
        cme_config
    else
        echo -e "Initializing cme"
        crackmapexec
        cme_config
    fi

    echo 'Adding custom Bloodhound queries'
    wget https://raw.githubusercontent.com/hausec/Bloodhound-Custom-Queries/master/customqueries.json -o ~/.config/bloodhound/customqueries.json


    # Neo4j
    wget -O - https://debian.neo4j.com/neotechnology.gpg.key | sudo apt-key add -
    echo 'deb https://debian.neo4j.com stable 4.0' > /etc/apt/sources.list.d/neo4j.list
    apt-get update
    apt-get install -y apt-transport-https neo4j
    systemctl stop neo4j
}


start_bh() {
    echo -e "Starting BloodHound!!!"
    cd $tools_path/BloodHound/BloodHound-linux-x64
    ./BloodHound --no-sandbox &
    
    # Add custom bloodhound queries from hausec (will need to refresh on first open)
    wget https://raw.githubusercontent.com/hausec/Bloodhound-Custom-Queries/master/customqueries.json -O '/home/'$SUDO_USER'/.config/bloodhound/customqueries.json'

    echo -e "Starting neo4j!!!"
    cd /usr/bin
    ./neo4j console 
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

    # SharPersist 1.0.1 (Jan 2020)
    wget https://github.com/mandiant/SharPersist/releases/download/v1.0.1/SharPersist.exe -O $win_compiled/SharPersist

    # LaZagne
    wget https://github.com/AlessandroZ/LaZagne/releases/download/2.4.3/lazagne.exe -O $win_compiled/lazagne.exe

    # GhostPack Compiled
    git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries.git $win_compiled/GhostPack

    # SharpHound
    wget https://github.com/BloodHoundAD/SharpHound/releases/download/v1.0.3/SharpHound-v1.0.3.zip -O $win_compiled/SharpHound/SharpHound.zip
    cd $win_compiled/SharpHound
    unzip SharpHound.zip

}

install_wl() {
    # Install additional wordlists
    # TODO
    # Fix rockyou
    cd /usr/share/wordlists
    gzip -dq /usr/share/wordlists/rockyou.txt.gz
    # Add additional wordlists
    git clone https://github.com/danielmiessler/SecLists.git /usr/share/wordlists/SecLists

}

add_aliases() {
    # nmap discovery
    # nmap detailed
    # parse
    # web scan
    alias discover
    alias hi='hi :)' # :)
    alias untar='tar -xf'
    alias www='python3 -m http.server 8080'
    alias ports='netstat -tulanp'
    #alias quick='todo'
    #alias full='todo'


}

basic_scripts() {
    # TODO 
    echo 'TODO Create basic scirpts'

}



payload_creation () {
    #nimcrypt

    #packmypayload
    git clone https://github.com/mgeeky/PackMyPayload.git $payload_mod/packmypayload
    cd $payload_mod/packmypayload
    pip install --upgrade pip setuptools wheel
    python3 -m pip install -r requirements.txt

    #nimpact
    git clone https://github.com/chvancooten/NimPackt-v1.git $payload_mod/nimpact
    cd $payload_mod/nimpact
    apt install -y nim
    pip3 install pycryptodome argparse
    nimble install -y winim nimcrypto

    #uru
    git clone https://github.com/guervild/uru.git $payload_mod/uru
    cd $payload_mod/uru
    go install mvdan.cc/garble@latest
    go get github.com/C-Sto/BananaPhone
    go install github.com/guervild/uru@latest

    #ftp
    git clone https://github.com/Unknow101/FuckThatPacker.git $payload_mod/ftp

    # AVSignSeek (not payload creation, but used to detect where binary/paload is triggered in AV)
    git clone https://github.com/hegusung/AVSignSeek.git $payload_mod/AVSignSeek

    # darkarmour
    git clone https://github.com/bats3c/darkarmour $payload_mod/darkarmour
    apt -y install mingw-w64-tools mingw-w64-common g++-mingw-w64 gcc-mingw-w64 upx-ucl osslsigncode
    
    # ScareCrow
    git clone https://github.com/optiv/ScareCrow.git $payload_mod/ScareCrow
    go get github.com/fatih/color
    go get github.com/yeka/zip
    go get github.com/josephspurrier/goversioninfo
    apt-get install -y openssl osslsigncode mingw-w64
    go build %tools_path/ScareCrow/ScareCrow.go
    
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
    cd $payload_mod/mangle
    go get github.com/Binject/debug/pe
    go install github.com/optiv/Mangle@latest

    # Freeze
    git clone https://github.com/optiv/Freeze.git $payload_mod/Freeze
    cd $payload_mod/Freeze
    go build Freeze

}

options () {
    clear
    echo -e "\n    Select an option from menu:"                      
    echo -e "\n Key  Menu Option:               Description:"
    echo -e " ---  ------------               ------------"
    echo -e "  1 - Basic Install              Run commands (5,6,7)" # TODO - organize the basic install 
    echo -e "  2 - Install All                Run all of the commands below (1-5)"    
    echo -e "  3 - Install Windows binaries   Install Windows binaries into " $win_compiled       
    echo -e "  4 - Install Windows source     Install Windows source into " $win_source                      
    echo -e "  5 - Install Linux tools        Install common Linux tools into " $tools_path  
    echo -e "  6 - Instal BOFs                Install Cobalt Strike agressor scripts into " $agressor_path      
    echo -e "  7 - Payload Creation           Install tools for payload creation/modification into" $payload_creation                      
    echo -e "  8 - Start BloodHound           Start Neo4j and BloodHound (installs if not already installed)"
    echo -e "  9 - Add aliases (TODO)         TODO"
    echo -e "  w - Install wordlists (TODO)   Install additional wordlists"
    echo -e "  x - Exit                       Exit the setup script"                                      

    read -n1 -p "\n  Press key for menu item selection or press X to exit: " menu

    case $menu in
        1) install_tools;install_BOFs;payload_creation;;
        2) setup;install_go;win_binaries;install_tools;install_BOFs;payload_creation;;
        3) win_source;;
        4) win_binaries;;
        5) install_tools;;
        6) install_BOFs;;
        7) payload_creation;;
        8) check_bh;;
        9) add_aliases;;
        w) install_wl;;
        x) exit;;  
    esac

    #rerun menu?
}

# main
check_user
options
