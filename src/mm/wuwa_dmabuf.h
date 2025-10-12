#ifndef WUWA_DMABUF_H
#define WUWA_DMABUF_H

#include <linux/socket.h>

/**
 * do_create_dma_buf - Create a DMA buffer from a virtual address
 * @sock: Socket for session management
 * @arg: User-space pointer to wuwa_dma_buf_create_cmd
 *
 * This function creates a DMA buffer (dma-buf) from a process's virtual address,
 * allowing zero-copy memory sharing. The function:
 * 1. Translates the virtual address to a physical page
 * 2. Creates a scatter-gather table from the page
 * 3. Exports the page as a dma-buf file descriptor
 *
 * The resulting file descriptor can be used to map the memory into other processes
 * or hardware devices without copying data.
 *
 * Return: 0 on success, negative error code on failure
 */
int do_create_dma_buf(struct socket* sock, void* arg);

#endif /* WUWA_DMABUF_H */
