require grub2.inc

RDEPENDS:${PN}-common += "${PN}-editenv"
RDEPENDS:${PN} += "${PN}-common"
RDEPENDS:${PN}:class-native = ""

RPROVIDES:${PN}-editenv += "${PN}-efi-editenv"

PROVIDES:append:class-native = " grub-efi-native"

PACKAGES =+ "${PN}-editenv ${PN}-common"
FILES:${PN}-editenv = "${bindir}/grub-editenv"
FILES:${PN}-common = " \
    ${bindir} \
    ${sysconfdir} \
    ${sbindir} \
    ${datadir}/grub \
"
ALLOW_EMPTY:${PN} = "1"

do_install:append () {
    # Avoid conflicts with the EFI package for systems such as arm64 where we
    # need to build grub and grub-efi but only EFI is supported by removing EFI
    # from this package.
    # For native builds, we need to keep EFI modules for grub-mkimage to work
    if [ "${CLASSOVERRIDE}" = "class-native" ]; then
        # Keep EFI modules for native builds
        :
    else
        rm -rf ${D}${libdir}/grub/*-efi/
        rmdir --ignore-fail-on-non-empty ${D}${libdir}/grub ${D}${libdir}
    fi

    install -d ${D}${sysconfdir}/grub.d
    # Remove build host references...
    find "${D}" -name modinfo.sh -type f -exec \
        sed -i \
        -e 's,--sysroot=${STAGING_DIR_TARGET},,g' \
        -e 's|${DEBUG_PREFIX_MAP}||g' \
        -e 's:${RECIPE_SYSROOT_NATIVE}::g' \
        {} +
}

INSANE_SKIP:${PN} = "arch"
INSANE_SKIP:${PN}-dbg = "arch"

BBCLASSEXTEND = "native nativesdk"
