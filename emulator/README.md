# BBFW emulator

Example of using BBFW as a library and calling arbitrary functions (runs both under ARM and x86_64 using qemu-arm explicitly or implicitly via kernel binfmt)

See [Makefile](Makefile)

## Prereqs

### Requirements for Debian/Ubuntu:
```
apt install build-essential git make gcc-arm-linux-gnueabi qemu-user qemu-user-binfmt
```

### Requirements for Fedora:
- option 1 - using Arm GNU toolchain
  - go to https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads
  - scroll down to the section 'arm-none-linux-gnueabihf'
  - download the latest version of the AArch32 GNU/Linux target with hard float (arm-none-linux-gnueabihf) - currently the file name is arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz
  - extract it somewhere (for instance '/opt/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-linux-gnueabihf')
  - in the Makefile comment the lines for Debian and uncomment the lines for Fedora
- option 2 - using the arm-linux-gnueabi-toolchain from Fedora Copr
  - the packages are here: https://copr.fedorainfracloud.org/coprs/lantw44/arm-linux-gnueabi-toolchain/
  - install as follows:
```
dnf copr enable lantw44/arm-linux-gnueabi-toolchain 
dnf install arm-linux-gnueabi-{binutils,gcc,glibc}
```

Install qemu-user and binfmt:
```
dnf install qemu-user qemu-user-binfmt
```
