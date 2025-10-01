# How to Connect to the WuWa Driver

## Introduction

The WuWa driver is a custom kernel driver that provides low-level memory access and process manipulation capabilities. This guide explains how to establish a connection to the driver from userspace applications.

## Connection Mechanism

The WuWa driver uses a socket-based communication protocol. Unlike traditional character device drivers (`/dev/xxx`), it hijacks a network address family to provide a communication channel.

## Automatic Discovery

The recommended way to connect is using the automatic discovery algorithm:

### Algorithm Overview

1. **Iterate through candidate address families**
    - The driver is registered under one of several uncommon network protocol families
    - Common candidates include: Decnet, NetBeui, Security, Key, Ash, Econet, RDS, SNA, Irda, Pppox, Wanpipe, LLC, CAN, TIPC, Bluetooth, IUCV, RxRpc, ISDN, Phonet, IEEE802154, Caif, Alg, and Vsock

2. **Probe each family with a two-step test**
   ```
   Step 1: Try creating a SOCK_SEQPACKET socket
   Step 2: If ENOKEY error received, try SOCK_RAW socket
   ```

3. **Recognition signal**
    - When the correct family is probed with SOCK_SEQPACKET, the driver returns `-ENOKEY` (errno 126)
    - This unique error code serves as an identification marker
    - A subsequent SOCK_RAW socket creation on the same family will succeed

### Example Code (Rust)

```rust
use nix::sys::socket::{socket, AddressFamily, SockFlag, SockType};
use nix::errno::Errno;

fn connect_to_wuwa() -> Result<OwnedFd, Error> {
    let families = [
        AddressFamily::Decnet,
        AddressFamily::NetBeui,
        // ... (other families)
        AddressFamily::Vsock,
    ];

    for af in families.iter() {
        // Step 1: Probe with SeqPacket
        match socket(*af, SockType::SeqPacket, SockFlag::empty(), None) {
            Ok(_) => continue,  // Not our driver
            Err(Errno::ENOKEY) => {
                // Found it! Try Raw socket
                if let Ok(fd) = socket(*af, SockType::Raw, SockFlag::empty(), None) {
                    return Ok(fd);
                }
            }
            Err(_) => continue,  // Try next family
        }
    }
    
    Err(Error::DriverNotFound)
}
```

### Example Code (C)

```c
#include <sys/socket.h>
#include <errno.h>

int connect_to_wuwa() {
    int families[] = {
        AF_DECnet, AF_NETBEUI, AF_SECURITY, 
        AF_KEY, AF_NETLINK, /* ... */
    };
    
    for (int i = 0; i < sizeof(families)/sizeof(int); i++) {
        int fd = socket(families[i], SOCK_SEQPACKET, 0);
        
        if (fd >= 0) {
            close(fd);
            continue;
        }
        
        if (errno == ENOKEY) {
            // Found the driver!
            fd = socket(families[i], SOCK_RAW, 0);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    
    return -1;  // Driver not found
}
```

## Using the Connection

Once connected, the socket file descriptor is used to issue ioctl commands:

```rust
let sock_fd = connect_to_wuwa()?;

// Issue ioctl commands
ioctl(sock_fd, WUWA_IOCTL_FIND_PROCESS, &mut cmd);
```

## Requirements

- Root privileges (or CAP_NET_RAW capability)
- WuWa kernel module loaded
- Linux kernel with the hijacked protocol family available

## Troubleshooting

**Connection fails**: Ensure the kernel module is loaded with `lsmod | grep wuwa`

**Permission denied**: Run with root privileges or grant CAP_NET_RAW capability

**ENOKEY not returned**: The driver may be using a different address family. Check kernel logs for hints.

## Security Notice

This driver provides direct memory access capabilities and should only be used in controlled environments with proper authorization.