#include <taihen.h>
#include <psp2/paf.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/clib.h>
#include <psp2/registrymgr.h>

typedef struct picture_t picture_t;

typedef struct {
	int width;
	int height;
} dimensions_t;

typedef struct {
	void *field_0;
	void *field_4;
	void *field_8;
	int (*get_type)(picture_t *);
	int (*get_dimensions)(dimensions_t *, picture_t *);
	void *field_14;
	unsigned (*get_pixel)(picture_t *, int x, int y);
	void *field_1c;
	void *field_20;
} picture_vtable_t;

struct picture_t {
	picture_vtable_t *vptr;
};

typedef struct encode_t encode_t;

typedef struct {
	void *field_0;
	void *field_4;
	int (*is_buffer_init)(encode_t *);
	int (*append)(encode_t *, const void *buffer, size_t sz);
	void *field_10;
	void *field_14;
	void *field_18;
	void *field_1c;
	void *field_20;
} encode_vtable_t;

struct encode_t {
	encode_vtable_t *vptr;
} __attribute__((packed));

typedef struct {
	picture_t *picture;
	encode_t *encode;
	void *field_8;
} actual_encode_args_t;

typedef struct {
	int (*func)();
	unsigned field_4;
} unk_obj_t;

size_t g_png_size;

enum {
	ENCODE_ERROR1 = 0x80103001,
	ENCODE_ERROR = 0x80103002,
};

#define HookImport(module_name, library_nid, func_nid, func_name) ({ \
	taiHookFunctionImport(&func_name ## _ref, module_name, library_nid, func_nid, func_name ## _patch); \
})

#define HookOffset(modid, offset, thumb, func_name) ({ \
	taiHookFunctionOffset(&func_name ## _ref, modid, 0, offset, thumb, func_name ## _patch); \
})

int hex_dump(const void *addr, int size){

	addr = (const void *)(((uint32_t)addr) & ~0xF);

	size = (size + 0xF) & ~0xF;

	for(int i=0;i<size;i+=0x10){
		sceClibPrintf("0x%08X : %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n", (addr), ((char *)addr)[0x0], ((char *)addr)[0x1], ((char *)addr)[0x2], ((char *)addr)[0x3], ((char *)addr)[0x4], ((char *)addr)[0x5], ((char *)addr)[0x6], ((char *)addr)[0x7], ((char *)addr)[0x8], ((char *)addr)[0x9], ((char *)addr)[0xA], ((char *)addr)[0xB], ((char *)addr)[0xC], ((char *)addr)[0xD], ((char *)addr)[0xE], ((char *)addr)[0xF]);

		addr += 0x10;
	}

	return 0;
}

/*
 * BmpHeader by Princes of Sleeping
 */
typedef struct {
	char magic[2];                 // "BM"
	uint32_t full_file_size;       // 0x1FE08A : header size(0x8A) + image_size (960 * 544 * 4 : 0x1FE000)
	uint16_t rev[2];               // 0, 0
	uint32_t image_data_offset;    // 0xE + sub header size, 0x8A
} __attribute__((packed)) BmpHeader_t; // 0xE

typedef struct {
	uint32_t sub_header_size;  // 0x28
	uint32_t image_width_pix;
	uint32_t image_height_pix;
	uint16_t addr_0x1A_only_1; // 1
	uint16_t bit;              // 32 or 24
	uint32_t compression_type; // zero
	uint32_t image_size;
	char rsv1[0x10];
} __attribute__((packed)) BmpSubHeader28_t; // 0x28

typedef struct {
	uint32_t sub_header_size;  // 0x7C
	uint32_t image_width_pix;
	uint32_t image_height_pix;
	uint16_t addr_0x1A_only_1; // 1
	uint16_t bit;              // 32
	uint32_t compression_type; // 3
	//0x22
	uint32_t image_size;
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
	//0x36 - color code ?
	uint32_t unk5; // 0x00FF0000
	uint32_t unk6; // 0x0000FF00
	uint32_t unk7; // 0x000000FF
	uint32_t unk8; // 0xFF000000
	//0x46
	uint32_t BGRs_magic;
	char unk9[0x30];
	uint32_t unk10;// 2 ?
	char unk11[0xC];
} __attribute__((packed)) BmpSubHeader7C_t; // 0x7C

int get_system_screenshot_format(void){

	int res;
	int val = -1;

	res = sceRegMgrGetKeyInt("/CONFIG/PHOTO", "debug_screenshot_format", &val);
	if(res < 0)
		return res;

	if(val == 1)
		return 1; // bmp

	if(val == 0)
		return 0; // jpg

	return -1;
}

int encode_bmp(actual_encode_args_t *args)
{
	int res;
	dimensions_t wh;

	args->picture->vptr->get_dimensions(&wh, args->picture);

	BmpHeader_t BmpHeader;
	BmpSubHeader28_t BmpSubHeader28;

	sceClibMemset(&BmpHeader, 0, sizeof(BmpHeader_t));
	sceClibMemset(&BmpSubHeader28, 0, sizeof(BmpSubHeader28_t));

	BmpHeader.magic[0] = 'B';
	BmpHeader.magic[1] = 'M';
	BmpHeader.full_file_size = sizeof(BmpHeader_t) + sizeof(BmpSubHeader28_t) + (wh.width * wh.height * 4);
	BmpHeader.image_data_offset = sizeof(BmpHeader_t) + sizeof(BmpSubHeader28_t);

	BmpSubHeader28.sub_header_size  = sizeof(BmpSubHeader28);
	BmpSubHeader28.image_width_pix  = wh.width;
	BmpSubHeader28.image_height_pix = wh.height;
	BmpSubHeader28.addr_0x1A_only_1 = 1;
	BmpSubHeader28.bit              = 32;
	BmpSubHeader28.compression_type = 0;
	BmpSubHeader28.image_size       = (wh.width * wh.height * 4);

	res = sizeof(BmpHeader_t);
	args->encode->vptr->append(args->encode, &BmpHeader, sizeof(BmpHeader_t));

	res += sizeof(BmpSubHeader28_t);
	args->encode->vptr->append(args->encode, &BmpSubHeader28, sizeof(BmpSubHeader28_t));

	int *pixels;
	pixels = sce_paf_private_malloc(wh.width * 4);

	uint32_t color32[4];

	for (int i = wh.height - 1; i >= 0 ; --i) {

		// haven't reversed what this does, just copied from assembly
		unk_obj_t *unk = args->field_8;
		if (unk && unk->func && unk->func(unk->field_4)) {
			res = ENCODE_ERROR1;
			goto cleanup;
		}

		for (int j = wh.width - 1; j >= 0; --j){

			uint32_t color = args->picture->vptr->get_pixel(args->picture, j, i);

			color32[0] = (color >> 0) & 0xFF;
			color32[1] = (color >> 8) & 0xFF;
			color32[2] = (color >> 16) & 0xFF;

			pixels[j] = (color32[0] << 16) | (color32[1] << 8) | (color32[2] << 0) | 0xFF000000;
		}

		args->encode->vptr->append(args->encode, pixels, wh.width * 4);
		res += (wh.width * 4);
	}

cleanup:
	sce_paf_private_free(pixels);

	return res;
}

// disable watermark
tai_hook_ref_t shell_add_watermark_ref;
int shell_add_watermark_patch(int a1, int a2){
	return 0;
}

// Replace type = 2 encoding with any implementation
tai_hook_ref_t shell_encode_type2_ref;
int shell_encode_type2_patch(actual_encode_args_t *args)
{
	int res;

	if (args->encode == NULL)
		return ENCODE_ERROR;

	if (!args->encode->vptr->is_buffer_init(args->encode))
		return ENCODE_ERROR;

	if (args->picture == NULL)
		return ENCODE_ERROR;

	if (!args->picture->vptr->get_type(args->picture))
		return ENCODE_ERROR;


	res = get_system_screenshot_format();
	if(res < 0){
		res = encode_bmp(args);
	}else if(res == 0){ // for devkit jpg
		res = TAI_CONTINUE(int, shell_encode_type2_ref, args);
	}else if(res == 1){
		res = encode_bmp(args);
	}

	return res;
}

// enable type=2 screenshot encoding
tai_hook_ref_t shell_encode_screenshot_ref;
int shell_encode_screenshot_patch(void **ss_arg1, unsigned unk) {
	// set format to 2 = "raw" but we will hook and change that later

	if(get_system_screenshot_format() != 0){ // for devkit jpg
		((int*)(*ss_arg1))[8/4] = 2;
	}

	return TAI_CONTINUE(int, shell_encode_screenshot_ref, ss_arg1, unk);
}


// change extension from jpg to bmp
const char bmp_path[] = "ur0:temp/screenshot/capture.bmp";

// change branch for 0x34560004 (screenshot disable) to 0x34560003 (screenshot enable)
const char mov_r3_r7[] = {
	0x3B, 0x00, 0x00, 0x00
};

void _start() __attribute__ ((weak, alias ("module_start")));
int module_start(SceSize argc, const void *args){

	tai_module_info_t info;
	info.size = sizeof(info);
	if(taiGetModuleInfo("SceShell", &info) != 0){
		return SCE_KERNEL_START_FAILED;
	}

	switch (info.module_nid) {
	case 0x0552F692: // 3.60 Retail
		HookOffset(info.modid, 0x247e00, 1, shell_add_watermark);
		HookOffset(info.modid, 0x365f46, 1, shell_encode_screenshot);
		HookOffset(info.modid, 0x36bd22, 1, shell_encode_type2);
		taiInjectData(info.modid, 0, 0x248840, mov_r3_r7, 2);
		taiInjectData(info.modid, 0, 0x5148b8, bmp_path, sceClibStrnlen(bmp_path, 0xFFFF) + 1);
        break;
	case 0xEAB89D5C: // 3.60 Testkit
		HookOffset(info.modid, 0x240234, 1, shell_add_watermark);
		HookOffset(info.modid, 0x35c98e, 1, shell_encode_screenshot);
		HookOffset(info.modid, 0x36276a, 1, shell_encode_type2);
		taiInjectData(info.modid, 0, 0x240C74, mov_r3_r7, 2);
		taiInjectData(info.modid, 0, 0x508B18, bmp_path, sceClibStrnlen(bmp_path, 0xFFFF) + 1);
        break;
	case 0x6CB01295: // 3.60 Devkit
		HookOffset(info.modid, 0x23b8a8, 1, shell_add_watermark);
		HookOffset(info.modid, 0x35809a, 1, shell_encode_screenshot);
		HookOffset(info.modid, 0x35de76, 1, shell_encode_type2);
        break;
	case 0x5549BF1F: // 3.65 Retail
	case 0x34B4D82E: // 3.67 Retail
	case 0x12DAC0F3: // 3.68 Retail
		HookOffset(info.modid, 0x247e9c, 1, shell_add_watermark);
		HookOffset(info.modid, 0x36638a, 1, shell_encode_screenshot);
		HookOffset(info.modid, 0x36c166, 1, shell_encode_type2);
		taiInjectData(info.modid, 0, 0x2488dc, mov_r3_r7, 2);
		taiInjectData(info.modid, 0, 0x514df8, bmp_path, sceClibStrnlen(bmp_path, 0xFFFF) + 1);
        break;

	default:
		sceClibPrintf("unknown SceShell, NID:0x%08X\n", info.module_nid);
		return SCE_KERNEL_START_FAILED;
        break;

	}

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args) {
	return SCE_KERNEL_STOP_SUCCESS;
}
