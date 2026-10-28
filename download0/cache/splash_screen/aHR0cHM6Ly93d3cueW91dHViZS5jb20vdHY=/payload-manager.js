// Carga automatica de Payload Manager tras el ELF Loader de Y2JB.

(async function () {
    const PAYLOAD_NAME = "pldmgr.elf";
    const LOADER_PORT = 9021;
    const CACHE_DIR = "aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY=";

    function sceNetHtons(hostshort) {
        return ((hostshort & 0xff) << 8) | ((hostshort >> 8) & 0xff);
    }

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function file_exists(path) {
        const path_addr = alloc_string(path);
        const stat_buf = malloc(0x200n);
        return syscall(SYSCALL.stat, path_addr, stat_buf) === 0n;
    }

    function find_payload_file(filename) {
        for (let n = 0; n <= 2; n++) {
            const path =
                "/mnt/sandbox/" + TITLE_ID + "_00" + n +
                "/download0/cache/splash_screen/" + CACHE_DIR + "/" + filename;

            if (file_exists(path)) return path;
        }
        return null;
    }

    function read_file_to_buffer(path) {
        const path_addr = alloc_string(path);
        const stat_buf = malloc(0x200n);

        if (syscall(SYSCALL.stat, path_addr, stat_buf) !== 0n) {
            throw new Error("stat failed: " + path);
        }

        const file_size = Number(read64(stat_buf + 72n));
        if (file_size <= 0) {
            throw new Error("invalid file size: " + path);
        }

        const fd = syscall(SYSCALL.open, path_addr, O_RDONLY, 0n);
        if (fd < 0n) {
            throw new Error("open failed: " + path);
        }

        const buffer = malloc(BigInt(file_size));
        let total = 0n;

        try {
            while (total < BigInt(file_size)) {
                const bytes = syscall(
                    SYSCALL.read,
                    fd,
                    buffer + total,
                    BigInt(file_size) - total
                );

                if (bytes <= 0n) {
                    throw new Error("short read: " + path);
                }

                total += bytes;
            }
        } finally {
            syscall(SYSCALL.close, fd);
        }

        return { buffer, size: file_size };
    }

    function make_localhost_sockaddr(port) {
        const sockaddr = malloc(16n);

        write8(sockaddr + 0n, 16n);
        write8(sockaddr + 1n, AF_INET);
        write16(sockaddr + 2n, BigInt(sceNetHtons(port)));
        write8(sockaddr + 4n, 127n);
        write8(sockaddr + 5n, 0n);
        write8(sockaddr + 6n, 0n);
        write8(sockaddr + 7n, 1n);

        return sockaddr;
    }

    async function wait_for_elf_loader() {
        for (let attempt = 0; attempt < 100; attempt++) {
            const sockfd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);

            if (sockfd >= 0n) {
                const enable = malloc(4n);
                write32(enable, 1n);

                syscall(
                    SYSCALL.setsockopt,
                    sockfd,
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    enable,
                    4n
                );

                const sockaddr = make_localhost_sockaddr(LOADER_PORT);
                const connected = syscall(
                    SYSCALL.connect,
                    sockfd,
                    sockaddr,
                    16n
                );

                syscall(SYSCALL.close, sockfd);

                if (connected >= 0n) return true;
            }

            await sleep(200);
        }

        return false;
    }

    try {
        // Espera a que main.js termine el exploit y elfldr quede activo.
        const loader_ready = await wait_for_elf_loader();

        if (!loader_ready) {
            await log("[-] Payload Manager: ELF Loader no activo en 127.0.0.1:" + LOADER_PORT);
            return;
        }

        await log("[*] ELF Loader activo. Cargando Payload Manager...");

        const payload_path = find_payload_file(PAYLOAD_NAME);

        if (!payload_path) {
            await log("[-] Payload Manager: no se encontro " + PAYLOAD_NAME);
            return;
        }

        const { buffer, size } = read_file_to_buffer(payload_path);
        await log("[*] Payload Manager: " + size + " bytes");

        const sockfd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sockfd < 0n) {
            throw new Error("socket creation failed");
        }

        const enable = malloc(4n);
        write32(enable, 1n);

        syscall(
            SYSCALL.setsockopt,
            sockfd,
            SOL_SOCKET,
            SO_REUSEADDR,
            enable,
            4n
        );

        const sockaddr = make_localhost_sockaddr(LOADER_PORT);
        const connected = syscall(SYSCALL.connect, sockfd, sockaddr, 16n);

        if (connected < 0n) {
            syscall(SYSCALL.close, sockfd);
            throw new Error("connect to ELF Loader failed");
        }

        const sent = syscall(SYSCALL.write, sockfd, buffer, BigInt(size));
        syscall(SYSCALL.close, sockfd);

        if (sent < 0n) {
            throw new Error("failed to send pldmgr.elf");
        }

        await log("[+] Payload Manager cargado");
    } catch (error) {
        await log("[-] Payload Manager: " + error.message);
    }
})();
