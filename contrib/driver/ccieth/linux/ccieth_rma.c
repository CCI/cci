/*
 * CCI over Ethernet
 *
 * Copyright © 2010-2012 Inria.  All rights reserved.
 * $COPYRIGHT$
 */

#include <ccieth_common.h>
#include <ccieth_wire.h>

#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/idr.h>

#define CCIETH_RMA_PAGES_VMALLOC_THRESHOLD 4096

struct ccieth_rma_handle {
	int id;
	int protection;

	struct page ** pages;
	unsigned long nr_pages;
	unsigned first_page_offset;

	int vmalloced;
	struct list_head endpoint_destroy_list_elt;
};

static void
ccieth_destroy_rma_handle(struct ccieth_rma_handle *handle)
{
	unsigned long i;

	might_sleep();

	for(i = 0; i < handle->nr_pages; i++) {
		struct page * page = handle->pages[i];
		set_page_dirty(page); /* FIXME only if handle was written */
		put_page(page);
	}

	if (handle->vmalloced)
		vfree(handle->pages);
	else
		kfree(handle->pages);
	kfree(handle);
}

static int
ccieth_destroy_rma_handle_idrforeach_cb(int id, void *p, void *data)
{
        struct ccieth_rma_handle *handle = p;
        struct list_head *tmplist = data;

	/* FIXME: check status ? */

        list_add(&handle->endpoint_destroy_list_elt, tmplist);
        return 0;
}

void
ccieth_destroy_endpoint_rma_handles(struct ccieth_endpoint *ep)
{
	struct ccieth_rma_handle *handle, *nhandle;
	struct list_head destroy_handle_list;
	int destroyed_handle;

	/* cannot idr_remove from within idr_for_each.
	 * place the handles on a temporary list.
	 */
	INIT_LIST_HEAD(&destroy_handle_list);
	idr_for_each(&ep->rma_handle_idr, ccieth_destroy_rma_handle_idrforeach_cb,
		     &destroy_handle_list);

	destroyed_handle = 0;
	list_for_each_entry_safe(handle, nhandle, &destroy_handle_list, endpoint_destroy_list_elt) {
		idr_remove(&ep->rma_handle_idr, handle->id);
		ccieth_destroy_rma_handle(handle);
		destroyed_handle++;
	}
	dprintk("destroyed %d rma handles on endpoint destroy\n", destroyed_handle);
}

int ccieth_rma_register(struct ccieth_endpoint *ep,
			struct ccieth_ioctl_rma_register *rr)
{
	struct ccieth_rma_handle *handle;
	unsigned long nr_pages;
	unsigned first_page_offset;
	struct page **pages;
	int err;
	int id;

	err = -ENOMEM;
	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (unlikely(!handle))
		goto out;

	first_page_offset = rr->buffer_ptr & (PAGE_SIZE-1);
	nr_pages = (rr->buffer_len + first_page_offset + PAGE_SIZE-1)/PAGE_SIZE;

	/* get a rma handle id (only reserve it */
#ifdef CCIETH_HAVE_IDR_PRELOAD
	idr_preload(GFP_KERNEL);
	spin_lock(&ep->rma_handle_idr_lock);
        err = idr_alloc(&ep->rma_handle_idr, NULL, 0, 0, GFP_NOWAIT);
	spin_unlock(&ep->rma_handle_idr_lock);
        idr_preload_end();
        if (err < 0)
                goto out_with_handle;
        id = err;
#else /* !CCIETH_HAVE_IDR_PRELOAD */
retry:
	spin_lock(&ep->rma_handle_idr_lock);
	err = idr_get_new(&ep->rma_handle_idr, NULL, &id);
	spin_unlock(&ep->rma_handle_idr_lock);
	if (err == -EAGAIN) {
		if (idr_pre_get(&ep->rma_handle_idr, GFP_KERNEL) > 0)
			goto retry;
		err = -ENOMEM;
		goto out_with_handle;
	}
#endif /* !CCIETH_HAVE_IDR_PRELOAD */

	if (nr_pages <= CCIETH_RMA_PAGES_VMALLOC_THRESHOLD) {
		pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
		handle->vmalloced = 0;
	} else {
		pages = vmalloc(nr_pages * sizeof(*pages));
		handle->vmalloced = 1;
	}
	err = -ENOMEM;
	if (unlikely(!pages))
		goto out_with_id;

	err = get_user_pages_fast(rr->buffer_ptr & ~(PAGE_SIZE-1), nr_pages,
				  (rr->protection & PROT_WRITE) != 0,
				  pages);
	if (err >= 0 && err < nr_pages) {
		int i;
		for(i=0; i<err; i++)
			put_page(pages[i]);
		err = -EFAULT;
		goto out_with_pages;
	}

	handle->protection = rr->protection;
	handle->first_page_offset = first_page_offset;
	handle->nr_pages = nr_pages;
	handle->pages = pages;
	handle->id = id;
	idr_replace(&ep->rma_handle_idr, handle, id);

	rr->handle = (uint64_t) id;
	return 0;

out_with_pages:
	if (handle->vmalloced)
		vfree(handle->pages);
	else
		kfree(handle->pages);
out_with_id:
	spin_lock(&ep->rma_handle_idr_lock);
	idr_remove(&ep->rma_handle_idr, id);
	spin_unlock(&ep->rma_handle_idr_lock);
out_with_handle:
	kfree(handle);
out:
	return err;
}

int ccieth_rma_deregister(struct ccieth_endpoint *ep,
			  struct ccieth_ioctl_rma_deregister *dr)
{
	struct ccieth_rma_handle *handle;
	int err = 0;

	spin_lock(&ep->rma_handle_idr_lock);
	handle = idr_find(&ep->rma_handle_idr, (int) dr->handle);
	if (handle) {
		/* FIXME: check status ? */
		idr_remove(&ep->rma_handle_idr, (int) dr->handle);
	} else {
		err = -EINVAL;
	}
	spin_unlock(&ep->rma_handle_idr_lock);

	if (handle)
		ccieth_destroy_rma_handle(handle); /* may sleep */

	return err;
}

int ccieth_rma(struct ccieth_endpoint *ep,
	       struct ccieth_ioctl_rma *rm)
{
	struct ccieth_connection *conn;
	struct ccieth_driver_event *event = NULL;
	enum ccieth_msg_completion_type completion_type;
	struct ccieth_rcu_completion *completion = NULL;
	int err;

	err = -EINVAL;
	if (unlikely(rm->msg_len > ep->max_send_size))
		goto out;

	/* TODO */

	return -ENOSYS;

out:
	return err;
}
