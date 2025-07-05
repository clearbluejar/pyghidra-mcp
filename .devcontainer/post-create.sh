# Create local venv
python3 -m venv .env
source .env/bin/activate

# upgrade pip
pip install --upgrade pip

# Download latest pyi typings
pip install ghidra-stubs

# Install pyhdira
pip install pyghidra

# Install uv
pip install uv

# install local workspace and test requirements
pip install -e ".[cli]"

# If arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    if [ -e $GHIDRA_INSTALL_DIR/support/buildNatives ]
    then
        $GHIDRA_INSTALL_DIR/support/buildNatives
    else
        # needed for Ghidra 11.2+
        pushd $GHIDRA_INSTALL_DIR/support/gradle/
        gradle buildNatives
        popd
    fi
else
    ## temporary - fix intel 64 docker image with missing packages
    sudo apt update
    sudo apt install -y libxtst6 libxi-dev
fi

# Setup Ghidra Dev for Reference
# git clone https://github.com/NationalSecurityAgency/ghidra.git ~/ghidra-master
# pushd ~/ghidra-master

# # Follow setup from https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md
# gradle -I gradle/support/fetchDependencies.gradle init
# gradle prepdev

# popd

# echo 'To open up a Ghidra latest dev: code ~/ghidra-master'