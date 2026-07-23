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
#include <linux/file.h>
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

/* ── Try to find property in given context file ─────────────── */
/* Open the property context file and walk the trie for key.
 * Returns the file pointer with trie data read, or NULL. */
static struct file *try_context(const char *context, const char *key,
				uint8_t **out_page, size_t *out_page_size,
				uint32_t *out_info_off)
{
	char path[256];
	struct file *fp;
	struct prop_area_header hdr;
	loff_t pos = 0;
	uint8_t *page = NULL;
	uint32_t info_off;

	snprintf(path, sizeof(path),
		 "/dev/__properties__/u:object_r:%s:s0", context);
	fp = filp_open(path, O_RDWR, 0);
	if (IS_ERR(fp))
		return NULL;

	kernel_read(fp, &hdr, sizeof(hdr), &pos);
	if (hdr.magic != PROP_AREA_MAGIC) {
		fput(fp);
		return NULL;
	}

	*out_page_size = hdr.bytes_used + PROP_AREA_HEADER_SZ;
	page = kzalloc(*out_page_size, GFP_KERNEL);
	if (!page) {
		fput(fp);
		return NULL;
	}
	pos = 0;
	kernel_read(fp, page, *out_page_size, &pos);

	info_off = prop_trie_find(page + PROP_AREA_HEADER_SZ, key);
	if (!info_off) {
		kfree(page);
		fput(fp);
		return NULL;
	}

	*out_page = page;
	*out_info_off = info_off;
	return fp;
}

/* Context files to try, in order. Mapped from plat_property_contexts
 * on LineageOS 20 (verified at runtime with dd + strings + O_RDWR test).
 *
 * build_prop:           ro.build.type, ro.build.flavor, ro.build.display.id,
 *                       ro.build.user, ro.build.host
 * userdebug_or_eng_prop: ro.debuggable
 * default_prop:         ro.lineage.* (×8), ro.modversion (wildcard rule: *) */
static const char *prop_contexts[] = {
	"build_prop",
	"userdebug_or_eng_prop",
	"default_prop",
	NULL,
};

/* ── Property set / delete ──────────────────────────────────── */
int property_set(const char *key, const char *value)
{
	struct file *fp = NULL;
	uint8_t *page = NULL;
	uint32_t info_off;
	size_t page_size;
	int vlen = strlen(value);
	int ret = -ENOENT;
	int i;

	for (i = 0; prop_contexts[i]; i++) {
		fp = try_context(prop_contexts[i], key, &page,
				 &page_size, &info_off);
		if (fp)
			break;
	}

	if (!fp) {
		pr_debug("susfs: property '%s' not in any context\n", key);
		return -ENOENT;
	}

	if (vlen >= PROP_VALUE_MAX)
		vlen = PROP_VALUE_MAX - 1;

	/* Write new value into shared memory */
	{
		loff_t pos;

		pos = (loff_t)info_off + offsetof(struct prop_info_rec, value);
		kernel_write(fp, value, vlen, &pos);
		pos = (loff_t)info_off + offsetof(struct prop_info_rec, value) + vlen;
		kernel_write(fp, "\0", 1, &pos);
	}

	/* Bump serial to notify readers */
	{
		uint32_t new_serial;
		loff_t pos;

		memcpy(&new_serial, page + info_off +
		       offsetof(struct prop_info_rec, serial),
		       sizeof(new_serial));
		new_serial += 2;
		pos = (loff_t)info_off +
		      offsetof(struct prop_info_rec, serial);
		kernel_write(fp, &new_serial, sizeof(new_serial), &pos);
	}

	pr_info("susfs: property_set '%s' = '%s' (context=%s)\n",
		key, value, prop_contexts[i]);
	ret = 0;

	kfree(page);
	fput(fp);
	return ret;
}

int property_delete(const char *key)
{
	struct file *fp = NULL;
	uint8_t *page = NULL;
	uint32_t info_off;
	size_t page_size;
	int ret = -ENOENT;
	int i;

	for (i = 0; prop_contexts[i]; i++) {
		fp = try_context(prop_contexts[i], key, &page,
				 &page_size, &info_off);
		if (fp)
			break;
	}

	if (!fp) {
		pr_debug("susfs: property '%s' not in any context\n", key);
		return -ENOENT;
	}

	/* Zero out name first byte to mark deleted */
	{
		char nul = '\0';
		loff_t pos = (loff_t)info_off + sizeof(struct prop_info_rec);
		kernel_write(fp, &nul, 1, &pos);
	}

	/* Clear value */
	{
		char nul = '\0';
		loff_t pos = (loff_t)info_off + offsetof(struct prop_info_rec, value);
		kernel_write(fp, &nul, 1, &pos);
	}

	/* Bump serial */
	{
		uint32_t new_serial;
		loff_t pos;
		memcpy(&new_serial, page + info_off +
		       offsetof(struct prop_info_rec, serial),
		       sizeof(new_serial));
		new_serial += 2;
		pos = (loff_t)info_off +
		      offsetof(struct prop_info_rec, serial);
		kernel_write(fp, &new_serial, sizeof(new_serial), &pos);
	}

	pr_info("susfs: property_delete '%s' (context=%s)\n",
		key, prop_contexts[i]);

	kfree(page);
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
