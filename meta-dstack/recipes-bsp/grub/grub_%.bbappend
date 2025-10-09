# Ensure grub-native builds with EFI support for CSV machines
GRUBPLATFORM:class-native = "efi"

# For native builds, ensure EFI modules are installed
do_install:append:class-native() {
    # Ensure EFI modules are installed for native builds
    # The autotools build may not install all EFI modules by default
    oe_runmake 'DESTDIR=${D}' -C grub-core install
    
    # Ensure moddep.lst is created for EFI platform
    install -d ${D}${libdir}/grub/x86_64-efi
    
    # Generate moddep.lst if it doesn't exist
    if [ ! -f ${D}${libdir}/grub/x86_64-efi/moddep.lst ]; then
        # Create a basic moddep.lst file
        echo "# Module dependencies for x86_64-efi" > ${D}${libdir}/grub/x86_64-efi/moddep.lst
        echo "depends bli part_gpt" >> ${D}${libdir}/grub/x86_64-efi/moddep.lst
    fi
    
    # Ensure all necessary EFI modules are installed
    if [ -d ${B}/grub-core ]; then
        install -d ${D}${libdir}/grub/x86_64-efi
        # Copy any .mod files that might be missing
        find ${B}/grub-core -name "*.mod" -exec install -m 644 {} ${D}${libdir}/grub/x86_64-efi/ \;
    fi
    
    # Create missing EFI modules if they don't exist
    # Some modules might have different names in EFI vs BIOS
    if [ ! -f ${D}${libdir}/grub/x86_64-efi/linuxefi.mod ] && [ -f ${D}${libdir}/grub/x86_64-efi/linux.mod ]; then
        ln -sf linux.mod ${D}${libdir}/grub/x86_64-efi/linuxefi.mod
    fi
    
    # Create sevsecret.mod alias for crypto.mod (for EDK2 compatibility)
    if [ ! -f ${D}${libdir}/grub/x86_64-efi/sevsecret.mod ] && [ -f ${D}${libdir}/grub/x86_64-efi/crypto.mod ]; then
        ln -sf crypto.mod ${D}${libdir}/grub/x86_64-efi/sevsecret.mod
    fi
    
    # Create a wrapper script for grub-mkimage that sets the correct paths
    install -d ${D}${bindir}
    
    # Backup the original grub-mkimage if it exists
    if [ -f ${D}${bindir}/grub-mkimage ]; then
        mv ${D}${bindir}/grub-mkimage ${D}${bindir}/grub-mkimage.orig
    fi
    
    cat > ${D}${bindir}/grub-mkimage << 'EOF'
#!/bin/bash
# Wrapper script for grub-mkimage to ensure correct module paths
# Find the grub-mkimage.orig in the same directory
SCRIPT_DIR="$(dirname "$0")"
ORIG_GRUB_MKIMAGE="${SCRIPT_DIR}/grub-mkimage.orig"

# Set the correct module directory path
GRUB_MODULES_PATH="${SCRIPT_DIR}/../lib/grub/x86_64-efi"
export GRUB_MODULES_PATH

# Also set the grub directory for compatibility
GRUB_DIR="${SCRIPT_DIR}/../lib/grub"
export GRUB_DIR

# Call the original grub-mkimage with the correct module directory
if [ -f "${ORIG_GRUB_MKIMAGE}" ]; then
    exec "${ORIG_GRUB_MKIMAGE}" -d "${SCRIPT_DIR}/../lib/grub/x86_64-efi" "$@"
else
    echo "Error: Cannot find grub-mkimage.orig at ${ORIG_GRUB_MKIMAGE}" >&2
    exit 1
fi
EOF
    chmod +x ${D}${bindir}/grub-mkimage
}
