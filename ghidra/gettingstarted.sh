#!/bin/bash
clear
echo -e "===X6100 Baseband Firmware SRE: Initial Setup for New Reversers===\n\nThis script will try to get you up to speed with where we are are in our progress reverse engineering the X6100's bbfw on Debian Linux. We hope this script will run to completion without errors, but we assume you might encounter some 'happy accidents' along the way that should at least point you in the right direction to get you set up as quickly and easily as possible. If one section breaks, try to find & fix the error and then try re-running: The script should skip parts that already went well.\n\nLet's get started! \n\n"

#ask user to provide the AES-256 Xiegu firmware decryption key. YOU WILL NEED TO FIND YOUR OWN KEY.
knownxkeymd5='68cc293ad24ad384a2da4f6c44a52af1  -'
while [[ ! $knownxkeymd5 == $yourxkeymd5 ]]; do
        if [[ -f xiegu.key ]]; then
                echo "Found a Xiegu key from a previous run of this script. Trying that key."
                XKEY=`cat xiegu.key`
        else
                read -p "Please paste your Xiegu firmware decryption key here: " XKEY
        fi
        
        if [[ ! "${#XKEY}" == 64 ]]; then
                echo -e "   Invalid key: A valid key is 64 characters long and has the format\n   4841434b5445482d504c4e4554202020594f55524b45592048455245504c5a21\n   (Note: THIS EXAMPLE KEY IS NOT THE REAL KEY)\n   Please try again...\n"
                rm xiegu.key
        else
                yourxkeymd5=$(echo -n "${XKEY}" | sed 's/.*/\L&/g' | md5sum) #converts user's key to lowercase and then hashes it
                if [[ ! $knownxkeymd5 == $yourxkeymd5 ]]; then
                        echo -e "   Invalid key\n   Please try again...\n"
                        rm xiegu.key
                else
                        echo -e "   Key is valid! \n"
                        echo -n "${XKEY}" >| xiegu.key
                fi
        fi
done

#install ghidra
if [ ! -f /opt/ghidra_*/ghidraRun ]; then
        ### install ghidra to /opt/. ###
        GHIDRA_DL=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest | sed 's/[()",{}]/ /g; s/ /\n/g' | grep "https.*releases/download.*zip")
        wget -P ~/Downloads $GHIDRA_DL
        sudo unzip -d /opt/ ~/Downloads/ghidra_*.zip
        ### done installing ghidra ###
fi
sudo chown -R $USER /opt/ghidra_*
sudo chown -R :$USER /opt/ghidra_*
sudo chmod -R a+rwX,o-w /opt/ghidra_*
GHIDRA_HOME=$(find /opt/ghidra*/ghidraRun | grep -P -o "(.*)(?=/ghidraRun)")
export GHIDRA_INSTALL_DIR="${GHIDRA_HOME}" # set this to your ghidra installation directory

#clone repos
sudo apt-get install -y git
git -C ~/Downloads clone https://github.com/fventuri/BBFW.git
sudo cp ~/Downloads/BBFW/outputs/functions-X6100_BBFW_V1.1.6_221112001.csv $GHIDRA_INSTALL_DIR/functions-X6100_BBFW_V1.1.6_221112001.csv #copy the latest X6100 discovered symbols list
git -C ~/Downloads clone https://github.com/OpenHamradioFirmware/G90Tools.git

#build BBFW STM32 Loader from repo (specifically requires jdk1.19 & gradle8.1.1)
if [ ! -f $GHIDRA_INSTALL_DIR/ghidra_*_STM32Loader.zip ]; then
        sudo apt-get install -y openjdk-19-jdk # install JDK 19 and set it to default jdk
        sudo update-java-alternatives --jre-headless -s java-1.19*
        if [ ! -f /opt/gradle-8.1.1/bin/gradle ]; then
                ### install gradle8.1.1 ###
                wget -P ~/Downloads https://downloads.gradle.org/distributions/gradle-8.1.1-all.zip
                sudo unzip -d /opt/ ~/Downloads/gradle-8.1.1-all.zip
                echo 'export PATH=/opt/gradle-8.1.1/bin:$PATH' | sudo tee -a ~/.bashrc
                export PATH=/opt/gradle-8.1.1/bin:$PATH
                ### done installing gradle8.1.1 ###
        fi
        cd ~/Downloads/BBFW/ghidra-stm32/extensions/STM32Loader
        gradle
        sudo mv dist/ghidra_*_STM32Loader.zip $GHIDRA_INSTALL_DIR/.
fi

#build STM32F427_437xx.gdt from repo
if [ ! -f $GHIDRA_INSTALL_DIR/STM32F427_437xx.gdt ]; then
        wget -P ~/Downloads https://web.archive.org/web/20230622050333/https://www.st.com/content/ccc/resource/technical/software/firmware/group1/42/1a/98/f3/14/b4/4b/81/stsw-stm32065_v1-9-0/files/stsw-stm32065_v1-9-0.zip/jcr:content/translations/en.stsw-stm32065_v1-9-0.zip || wget -P ~/Downloads https://web.archive.org/web/20230622050333/https://www.st.com/content/ccc/resource/technical/software/firmware/group1/42/1a/98/f3/14/b4/4b/81/stsw-stm32065_v1-9-0/files/stsw-stm32065_v1-9-0.zip/jcr:content/translations/en.stsw-stm32065_v1-9-0.zip # download official standard peripheral library
        sudo unzip -d /opt/ ~/Downloads/en.stsw-stm32065_v1-9-0.zip
        sudo $GHIDRA_INSTALL_DIR/support/analyzeHeadless /tmp tempproj -preScript ~/Downloads/BBFW/ghidra-stm32/scripts/CreateSTM32GDTArchive.py output_dir=$GHIDRA_INSTALL_DIR -deleteProject
fi

#download and decrypt X6100_BBFW_V1.1.6_221112001.xgf proper
if [[ ! $( md5sum $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.bin ) == "36eb378655ac5661a3e676a0b6caab02  $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.bin" ]]; then
        if [[ ! $( md5sum $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.xgf ) == "ffd7ee1477fcb20d23cdbdcbf8a0ddc3  $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.xgf" ]]; then
                # Extract Xiegu_X6100_Firmware_Upgrade_20221124.zip\Firmware\sdcard_20221124.img\1.img\usr\firmware\X6100_BBFW_V1.1.6_221112001.xgf
                sudo apt-get install -y p7zip-full
                wget -P ~/Downloads https://radioddity.s3.amazonaws.com/Xiegu_X6100_Firmware_Upgrade_20221124.zip || wget -P ~/Downloads https://web.archive.org/web/20230421024752/https://radioddity.s3.amazonaws.com/Xiegu_X6100_Firmware_Upgrade_20221124.zip
                mkdir ~/Downloads/bbfw_extract
                unzip -d ~/Downloads/bbfw_extract ~/Downloads/Xiegu_X6100_Firmware_Upgrade_20221124.zip
                rm ~/Downloads/Xiegu_X6100_Firmware_Upgrade_20221124.zip
                7z x ~/Downloads/bbfw_extract/Firmware/sdcard_20221124.img -o"${HOME}/Downloads/bbfw_extract/Firmware/"
                rm ~/Downloads/bbfw_extract/Firmware/sdcard_20221124.img
                rm ~/Downloads/bbfw_extract/Firmware/*.fat
                7z x ~/Downloads/bbfw_extract/Firmware/1.img -o"${HOME}/Downloads/bbfw_extract/Firmware/"
                rm ~/Downloads/bbfw_extract/Firmware/1.img
                mv ~/Downloads/bbfw_extract/Firmware/usr/firmware/X6100_BBFW_V1.1.6_221112001.xgf $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.xgf
                rm -rf ~/Downloads/bbfw_extract
        fi

        #decrypt your BBFW file (with g90tools & python3 < v3.10)
                ### install and run python3.9.0 inside PyEnv ###
                hash pyenv 2>/dev/null; RESULT=$?
                if [[ $RESULT == 1 ]]; then
                        echo "pyenv did not run when called. Installing pyenv."
                        curl https://pyenv.run | bash
                        sudo echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
                        sudo echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
                        sudo echo 'eval "$(pyenv init -)"' >> ~/.bashrc
                        sudo echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
                fi
                        export PYENV_ROOT="$HOME/.pyenv" # initialize Pyenv for this shell
                        export PATH="$PYENV_ROOT/bin:$PATH"
                        eval "$(pyenv init -)"
                        eval "$(pyenv virtualenv-init -)"
                if [[ ! -d ~/.pyenv/versions/3.9.0 ]]; then
                        sudo apt-get install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev openssl #Python deps
                        env PYTHON_CONFIGURE_OPTS="--enable-shared" pyenv install -v 3.9.0
                fi
                if [[ ! -d ~/.pyenv/versions/g90tools_python3.9.0 ]]; then
                        pyenv virtualenv 3.9.0 g90tools_python3.9.0 #create a new virtualenv
                        pyenv activate g90tools_python3.9.0
                        python3 -m pip install --upgrade pip
                        python3 -m pip install pycrypto
                        pyenv deactivate
                fi
                ### done installing python3.9.0 inside PyEnv ###
        pyenv activate g90tools_python3.9.0
        rm $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.bin
        python3 ~/Downloads/G90Tools/encryption/encryption.py "${XKEY}" decrypt $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.xgf $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.bin
        pyenv deactivate && pyenv global system #set system python back to default
fi

#download STM32F4 reference manuals
if [ ! -d ~/Downloads/STM32F4docs ]; then
        mkdir ~/Downloads/STM32F4docs
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://www.st.com/resource/en/datasheet/stm32f427zg.pdf || wget -P ~/Downloads/STM32F4docs https://web.archive.org/web/20230421023317/https://www.st.com/resource/en/datasheet/stm32f427zg.pdf # STM32F427xx STM32F429xx datasheet (stm32f427zg.pdf)
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://www.st.com/resource/en/datasheet/stm32f437vg.pdf || wget -P ~/Downloads/STM32F4docs https://web.archive.org/web/20240527133347/https://www.st.com/resource/en/datasheet/stm32f437vg.pdf # High-performance advanced line, Arm Cortex-M4 core with DSP and FPU, 1 Mbyte of Flash memory, 180 MHz CPU, ART Accelerator, Chrom-ART Accelerator, FSMC, HW crypto (stm32f427vg.pdf) - https://www.st.com/en/microcontrollers-microprocessors/stm32f437vg.html
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://www.st.com/resource/en/reference_manual/rm0090-stm32f405415-stm32f407417-stm32f427437-and-stm32f429439-advanced-armbased-32bit-mcus-stmicroelectronics.pdf || wget -P ~/Downloads/STM32F4docs https://web.archive.org/web/20221112094009/https://www.st.com/resource/en/reference_manual/rm0090-stm32f405415-stm32f407417-stm32f427437-and-stm32f429439-advanced-armbased-32bit-mcus-stmicroelectronics.pdf # STM32F427 Reference manual #RM0090 (rm0090-stm32f405415-stm32f407417-stm32f427437-and-stm32f429439-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://www.st.com/resource/en/programming_manual/pm0214-stm32-cortexm4-mcus-and-mpus-programming-manual-stmicroelectronics.pdf || wget -P ~/Downloads/STM32F4docs https://web.archive.org/web/20220708163955/https://www.st.com/resource/en/programming_manual/pm0214-stm32-cortexm4-mcus-and-mpus-programming-manual-stmicroelectronics.pdf # STM32 CortexM4 Programming manual #PM0214 (pm0214-stm32-cortexm4-mcus-and-mpus-programming-manual-stmicroelectronics.pdf)
        wget -O ~/Downloads/STM32F4docs/DUI0553.pdf --timeout=5 --tries=3 https://documentation-service.arm.com/static/5f2ac76d60a93e65927bbdc5?token= || wget -O ~/Downloads/STM32F4docs/DUI0553.pdf https://web.archive.org/web/20220302165628/https://documentation-service.arm.com/static/5f2ac76d60a93e65927bbdc5?token= #Cortex-M4 Devices Generic User Guide (DUI0553.pdf)
        sudo apt-get install xchm
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://web.archive.org/web/20230622050333/https://www.st.com/content/ccc/resource/technical/software/firmware/group1/42/1a/98/f3/14/b4/4b/81/stsw-stm32065_v1-9-0/files/stsw-stm32065_v1-9-0.zip/jcr:content/translations/en.stsw-stm32065_v1-9-0.zip # STM32F40x/41x/427/437/429/439xx DSP and Standard Peripherals Library and source code v1.9.0 #STSW-STM32065 (stm32f4xx_dsp_stdperiph_lib_um.chm)
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://www.st.com/resource/en/data_brief/stsw-stm32065.pdf || wget -P ~/Downloads/STM32F4docs https://web.archive.org/web/20210120040215/https://www.st.com/resource/en/data_brief/stsw-stm32065.pdf # STM32F4 DSP and standard peripherals library databrief
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://web.archive.org/web/20230707192857/https://www.gnu.org/software/libc/manual/pdf/libc.pdf # The GNU C Library Reference Manual
        wget -P ~/Downloads/STM32F4docs --timeout=5 --tries=3 https://kolegite.com/EE_library/standards/ARM_ABI/rtabi32.pdf #Run-time ABI for the Arm (abi-aa)
fi

#load data and firmware into our Ghidra STM32 BBFW symbols loader
if [ -d $HOME/X6100_BBFW_V1.1.6_221112001_ghidraproject.rep ]; then
        echo -e "\nNOTE: $HOME/X6100_BBFW_V1.1.6_221112001_ghidraproject.rep already exists! \n"
        echo -e "We will skip creating of a loaded Ghidra BBFW project! \nIf you would like the loader to run, please delete the X6100_BBFW_V1.1.6_221112001_ghidraproject.rep (and .gpr) Ghidra project that exists, then re-run this script."
else
        cp -rf ~/Downloads/BBFW/ghidra-stm32/scripts/AssignFunctionNamesAndTypes.py $GHIDRA_HOME
        cp ~/Downloads/BBFW/ghidra-stm32/scripts/AssignFunctionNamesAndTypes.properties $GHIDRA_HOME
        cd $GHIDRA_INSTALL_DIR # Ghidra will only look for GDT files in the same directory that this script is run from for some reason (even if we explicity tell it the directory to look for GDT files in)
        $GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME X6100_BBFW_V1.1.6_221112001_ghidraproject -import $GHIDRA_INSTALL_DIR/X6100_BBFW_V1.1.6_221112001.bin -loader STM32Loader -postScript $GHIDRA_INSTALL_DIR/AssignFunctionNamesAndTypes.py gdt_archives=STM32F427_437xx.gdt functions=$GHIDRA_INSTALL_DIR/functions-X6100_BBFW_V1.1.6_221112001.csv
fi

#welcome
echo -e "\nIf everything completed successfully, then you should be all set up to help us reverse engineer the x6100 baseband firmware:\n - Reference manuals have been downloaded to ~/Downloads/STM32F4docs\n - Ghidra has been installed into /opt/ \n - A Ghidra project file has been set up in your home directory and is waiting to be loaded into Ghidra\n - Please document any functions you reverse engineer on the BBFW GitHub page in a functions.csv file."
echo -e "\nTry running\n   $GHIDRA_INSTALL_DIR/./ghidraRun\nThen when Ghidra is running, go to File > Open Project > Home > X6100_BBFW_V1.1.6_221112001_ghidraproject.gpr > Open Project, then double-click on the .bin file in the menu. Once the file is open in the Code Browser, look to the bottom-left window (Data Type Manager) and right-click STM32F427_437xx and 'Apply Function Data Types' just for good measure."
