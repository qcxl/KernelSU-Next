// SPDX-License-Identifier: GPL-2.0-only
/*
 * properties.c - Direct Android property shared memory manipulation
 *
 * Walks the property trie from init's shared memory and overrides
 * ro.* properties that cannot be set via setprop (once-only restriction
 * in init's property service).  Equivalent to: resetprop -n <key> <value>
 *
 * The structures defined here match bionic's system_properties.h
 * (ABI stable since Android 8, verified by prop-rs-android crate).
 * Called from boot_event.c on_post_fs_data() at zygote exec time.
 */
#include <linux/fs.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/slab.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/uaccess.h>

/* ── Property area structures (bionic ABI) ───────────────────── */
#define PROP_AREA_MAGIC       0x504F5250   /* "PROP" LE */
#define PROP_AREA_HEADER_SZ   128
#define PROP_TRIE_NODE_SZ     20
#define PROP_NAME_MAX         32
#define PROP_VALUE_MAX        92

/* Header of /dev/__properties__ shared memory file (128 bytes) */
struct prop_area_header {
	uint32_t bytes_used;
	uint32_t serial;
	uint32_t magic;
	uint32_t version;
	uint32_t reserved[28];
};

/* Trie node (20-byte header + variable-length name) */
struct prop_trie_node {
	uint32_t namelen;
	uint32_t prop;       /* offset to prop_info, or 0 */
	uint32_t left;
	uint32_t right;
	uint32_t children;
	/* char name[] follows (namelen bytes, no NUL, 4-byte aligned) */
};

/* Property record (96-byte header + variable-length name) */
struct prop_info_rec {
	uint32_t serial;
	char     value[PROP_VALUE_MAX];
	/* char name[] follows */
};

/* ── Trie walk ──────────────────────────────────────────────── */
/* Property name comparison: LENGTH FIRST, then byte comparison.
 * This matches bionic's cmp_prop_name(). */
static int prop_name_cmp(const char *key, int key_len,
			 const char *node_name, int node_len)
{
	if (key_len < node_len) return -1;
	if (key_len > node_len) return  1;
	return memcmp(key, node_name, key_len);
}

/* Walk the binary trie to find a property.
 * @data: pointer to data[] (after the 128-byte header)
 * Returns offset of prop_info_rec within the file, or 0 if not found. */
static uint32_t prop_trie_find(uint8_t *data, const char *key)
{
	char buf[PROP_NAME_MAX];
	int key_len = strlen(key);
	int seg_start = 0;
	uint32_t offset = 0;

	while (1) {
		int seg_end = seg_start;
		while (seg_end < key_len && key[seg_end] != '.')
			seg_end++;
		int seg_len = seg_end - seg_start;
		memcpy(buf, key + seg_start, seg_len);

		/* Navigate to children */
		if (offset != 0) {
			struct prop_trie_node *node;
			node = (struct prop_trie_node *)(data + offset);
			offset = node->children;
		}
		if (offset == 0)
			return 0;

		/* Binary search among siblings (BST by length+bytes) */
		while (offset) {
			struct prop_trie_node *node;
			node = (struct prop_trie_node *)(data + offset);
			uint8_t *node_name = data + offset + PROP_TRIE_NODE_SZ;
			int cmp = prop_name_cmp(buf, seg_len,
						(const char *)node_name,
						node->namelen);
			if (cmp == 0) {
				if (seg_end >= key_len) {
					if (node->prop)
						return node->prop;
					return 0;
				}
				break;
			}
			if (cmp < 0)
				offset = node->left;
			else
				offset = node->right;
		}

		seg_start = seg_end + 1;
		if (seg_start > key_len)
			return 0;
	}
}

/* ── Find the property area file ────────────────────────────── */
/* Open the default property context file directly.
 * All our target properties (ro.build.*, ro.debuggable, ro.lineage.*)
 * fall under the default_prop SELinux context (plat_property_contexts
 * wildcard rule: "* u:object_r:default_prop:s0"). */
static struct file *find_prop_area_file(void)
{
	static const char *paths[] = {
		"/dev/__properties__/u:object_r:default_prop:s0",
		NULL,
	};
	struct file *fp;
	int i;

	for (i = 0; paths[i]; i++) {
		fp = filp_open(paths[i], O_RDWR, 0);
		if (!IS_ERR(fp))
			return fp;
		pr_debug("susfs: property area '%s' open failed (%ld)\n",
			 paths[i], PTR_ERR(fp));
	}

	pr_warn("susfs: no property area found\n");
	return NULL;
}

/* ── Property set / delete ──────────────────────────────────── */
int property_set(const char *key, const char *value)
{
	struct file *fp;
	struct prop_area_header hdr;
	loff_t pos = 0;
	uint8_t *page = NULL;
	uint32_t info_off;
	int vlen = strlen(value);
	int ret = 0;

	fp = find_prop_area_file();
	if (!fp) {
		pr_warn("susfs: property area not found, skip '%s'\n", key);
		return -ENOENT;
	}

	kernel_read(fp, &hdr, sizeof(hdr), &pos);
	if (hdr.magic != PROP_AREA_MAGIC) {
		pr_err("susfs: property area bad magic (0x%x)\n", hdr.magic);
		ret = -EINVAL;
		goto out;
	}

	page = kzalloc(hdr.bytes_used + PROP_AREA_HEADER_SZ, GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	pos = 0;
	kernel_read(fp, page, hdr.bytes_used + PROP_AREA_HEADER_SZ, &pos);

	info_off = prop_trie_find(page + PROP_AREA_HEADER_SZ, key);
	if (!info_off) {
		pr_debug("susfs: property '%s' not found\n", key);
		ret = -ENOENT;
		goto out_free;
	}

	if (vlen >= PROP_VALUE_MAX)
		vlen = PROP_VALUE_MAX - 1;

	/* Write new value into shared memory */
	pos = (loff_t)info_off + offsetof(struct prop_info_rec, value);
	kernel_write(fp, value, vlen, &pos);
	pos = (loff_t)info_off + offsetof(struct prop_info_rec, value) + vlen;
	kernel_write(fp, "\0", 1, &pos);

	/* Bump serial to notify readers */
	{
		uint32_t new_serial;
		memcpy(&new_serial, page + info_off +
		       offsetof(struct prop_info_rec, serial),
		       sizeof(new_serial));
		new_serial += 2;
		pos = (loff_t)info_off +
		      offsetof(struct prop_info_rec, serial);
		kernel_write(fp, &new_serial, sizeof(new_serial), &pos);
	}

	pr_info("susfs: property_set '%s' = '%s'\n", key, value);
	ret = 0;

out_free:
	kfree(page);
out:
	fput(fp);
	return ret;
}

int property_delete(const char *key)
{
	struct file *fp;
	struct prop_area_header hdr;
	loff_t pos = 0;
	uint8_t *page = NULL;
	uint32_t info_off;
	int ret = 0;

	fp = find_prop_area_file();
	if (!fp)
		return -ENOENT;

	kernel_read(fp, &hdr, sizeof(hdr), &pos);
	if (hdr.magic != PROP_AREA_MAGIC) {
		ret = -EINVAL;
		goto out;
	}

	page = kzalloc(hdr.bytes_used + PROP_AREA_HEADER_SZ, GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		goto out;
	}
	pos = 0;
	kernel_read(fp, page, hdr.bytes_used + PROP_AREA_HEADER_SZ, &pos);

	info_off = prop_trie_find(page + PROP_AREA_HEADER_SZ, key);
	if (!info_off) {
		pr_debug("susfs: property '%s' not found\n", key);
		ret = -ENOENT;
		goto out_free;
	}

	/* Zero out name first byte to mark deleted */
	{
		char nul = '\0';
		pos = (loff_t)info_off + sizeof(struct prop_info_rec);
		kernel_write(fp, &nul, 1, &pos);
	}

	/* Clear value */
	{
		char nul = '\0';
		pos = (loff_t)info_off + offsetof(struct prop_info_rec, value);
		kernel_write(fp, &nul, 1, &pos);
	}

	/* Bump serial */
	{
		uint32_t new_serial;
		memcpy(&new_serial, page + info_off +
		       offsetof(struct prop_info_rec, serial),
		       sizeof(new_serial));
		new_serial += 2;
		pos = (loff_t)info_off +
		      offsetof(struct prop_info_rec, serial);
		kernel_write(fp, &new_serial, sizeof(new_serial), &pos);
	}

	pr_info("susfs: property_delete '%s'\n", key);

out_free:
	kfree(page);
out:
	fput(fp);
	return ret;
}

/* ── Master entry point called from boot_event.c ─────────────── */
void susfs_restore_properties(void)
{
	static const char * const set_props[][2] = {
		{ "ro.build.type",        "user" },
		{ "ro.build.flavor",      "OnePlus8T-user" },
		{ "ro.build.display.id",  "RKQ1.211119.001" },
		{ "ro.debuggable",        "0" },
		{ "ro.build.user",        "jenkins" },
		{ "ro.build.host",        "rd-build-193" },
		{ NULL, NULL },
	};
	static const char * const del_props[] = {
		"ro.lineage.version",
		"ro.lineage.build.version",
		"ro.lineage.build.version.plat.rev",
		"ro.lineage.build.version.plat.sdk",
		"ro.lineage.device",
		"ro.lineage.display.version",
		"ro.lineage.releasetype",
		"ro.lineagelegal.url",
		"ro.modversion",
		NULL,
	};
	int i;

	for (i = 0; set_props[i][0]; i++)
		property_set(set_props[i][0], set_props[i][1]);

	for (i = 0; del_props[i]; i++)
		property_delete(del_props[i]);
}
