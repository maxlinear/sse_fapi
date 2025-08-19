/**************************************************************************

  Copyright (C) 2022-2025 MaxLinear, Inc.

  For licensing information, see the file 'LICENSE' in the root folder of
  this software module.

 *************************************************************************/

/**************************************************************************
 *     File Name  : fapi_img_auths.c					                  *
 *     Project    : UGW                                                   *
 *     Description: provides the APIs for image authentication            *
 *                                                                        *
 *************************************************************************/
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <crc32.h>
#include <arpa/inet.h>
#include <sys/mount.h>

#include "fapi_sec_service.h"
#include "fapi_img_auth.h"
#include "sec_upgrade.h"
#include "secure_boot.h"
#include "libfdt.h"
#include "ltq_api_include.h"
#include "help_error.h"
#include "help_logging.h"
#include "safe_str_lib.h"
#include "safe_lib.h"
#include "safe_mem_lib.h"
#ifdef LINUX_UPGRADE
#include <sys/mman.h>
#endif

#if defined(IMG_AUTH) || defined(LINUX_UPGRADE)
#define MAX_PATH_LEN 256
#define MAX_BUFFER_LENGTH 256
#define BLW_LENGTH 8 /* Number of bytes of singing header */
#define FILE_SIZE 500
#define ARRAY_SIZE(arr) (int)(sizeof(arr) / sizeof((arr)[0]))
#endif
#ifdef LINUX_UPGRADE
#ifdef IMG_AUTH
static int fapi_ssImgValidate(img_param_t *pxImgParam, uint8_t upgradeOrCommit);
#endif
int validate_nested_fit(const void *fit, img_param_t image_auth, int *currentimage);
int upgrade_nested_fit(const void *fit, img_param_t image_auth, int *earlyboot);
struct map_table {
	char name[MAX_FILE_NAME];
	char part[MAX_PATH_LEN];
	bool early_boot; 		/* to check for late/early boot */
};
static struct map_table map[] = {
	{ "uboot", "u-boot", true },//part name uboot in other board and u-boot in octopus
	{ "rbe", "rbe", true },
	{ "kernel", "kernel", false },
	{ "firmware", "tep_firmware", true },
	{ "rootfs", "kernel", false },
	{ "dtb", "dtb", false },
	{ "kernel-dtb", "kernel", false },
	{ "filesystem", "kernel", false },
	{ "tep", "tep", true }
};
#define UDT_NEW_IMAGE 11
#define UDT_IMAGE_RECOVERED 10
#define UDT_IMAGE_NO_ACTION 0
#define UPDATE_FILE  "/etc/scripts/upgrade_done.sh"
#define RECOVERED_FILE "/etc/scripts/upgrade_recovered.sh"
#define RBE 0x1
#define BOOTLOADER 0x2
#define TEP 0x4
#define ROOTFS 0x8
#define KERNEL 0x10
#define DTB 0x20
#define BOOTLOADERFIT 0x40
#define TEPFIT 0x80
#define KERNELDTBFIT 0x100 
#define ROOTFSFIT 0x200
#define ACTIVE_PART_NAME "active"
#define INACTIVE_PART_NAME "inactive"
/* Supported image list for software upgrade */
static const int image_list[] = {
	RBE,
	BOOTLOADER,
	TEP,
	ROOTFS|KERNEL|DTB,
	RBE|BOOTLOADER|TEP|ROOTFS|KERNEL|DTB,
	BOOTLOADERFIT,
	TEPFIT,
	KERNELDTBFIT|ROOTFSFIT,
	RBE|BOOTLOADERFIT|TEPFIT|ROOTFSFIT|KERNELDTBFIT,
};
#define ARRAY_SIZE(arr) (int)(sizeof(arr) / sizeof((arr)[0]))
#endif

static unsigned char sState[][20] = {
	"UPG_NONE", "UPG_REQ", "UPG_INPROG", "UPG_SUCC", "UPG_FAIL",
	"UPG_COMMIT_REQ", "UPG_COMMIT_SUCC", "UPG_COMMIT_FAIL", "UPG_RES"
};
#define DATA_SIZE 32
#define DEV_MODEL_NAME_SIZE 256

/* for other flash we need to see how fetch this count */
#define UBI_FLASH_CUR_CNT "cat /sys/class/ubi/ubi0/max_ec"
#define DEV_TREE_MODEL_FILE "/proc/device-tree/model"
#define LOCK_FILE "/opt/intel/etc/sse/sse_lock"
#define UPGRADE_PARTITION_NAND "/dev/ubi1_5"

#ifdef IMG_AUTH
#define EMMC_PAGE_SIZE 0x800
#define NAND_PAGE_SIZE 0x1000
static uint32_t image_multi_count(const image_header_t *hdr);
static int fapi_ssValidateFullImage(int nSecFd, img_param_t *pxImgParam);
static int fapi_ssvalidateImg(int nFd, void *addr, uint32_t size, uint8_t upgradeOrCommit);
static int fapi_ssValidateRootFS(int nFd, void *addr, uint32_t size);
static int fapi_ssValidateDTB(int nFd, const void *addr, uint8_t upgradeOrCommit);
static int is_image_dcrc_valid(image_header_t *hdr);
static int is_image_hcrc_valid(image_header_t *hdr);
#endif
#ifdef LINUX_UPGRADE
#ifdef IMG_AUTH
static int fapi_ssReadFromPartition(char *dev_path, char * type, long unsigned int len);
#endif
static char fapi_ssCheckActiveBank(void);
static int fapi_ssMountLateboot(char *mnt_part, char *mnt_path);
static void fapi_ssGetFileNameFromUboot(char *file_name, char *cPath);
static int fapi_ssWriteToPartition(const unsigned char *image_src_address, int image_len, char *dev_path);
static char *fapi_ssGetParitionNameEMMC(char *image_type, char bank);
#else
static int fapi_ssWriteToUpgPartition(img_param_t *pxImg);
#endif
extern int check_boardtype(void);
/*
 * Function to extract device name from partition name
 *
 * @name - name of the partition
 * @type - type of device to return for NAND flash:
 *         B/b - for block device /dev/mtdblockX (e.g. /dev/mtdblock16)
 *         C/c - for character device /dev/ubiX_Y (e.g. /dev/ubi1_0)
 */
extern char *getDevFromPartition(char *name, char type);


/**====================================================================
 * @brief  image header CRC  check
 *
 * @return
 *  UGW_SUCCESS on success
 *  UGW_FAILURE on failure
 ======================================================================
 */
static int is_image_hcrc_valid(image_header_t *hdr)
{
	uint32_t un_crc;
	int len = sizeof(image_header_t);
	image_header_t header;

	memmove(&header, (char *)hdr, len);
	header.img_hdr_hcrc = 0;

	un_crc = 0x00000000 ^ 0xffffffff;
	un_crc = crc32(un_crc, &header, len);

	un_crc ^= 0xffffffff;
	return (un_crc == ntohl(hdr->img_hdr_hcrc));
}

#ifdef IMG_AUTH
/**=====================================================================
 * @brief  image data CRC  check
 *
 * @return
 *  UGW_SUCCESS on success
 *  UGW_FAILURE on failure
 ========================================================================
 */
static int is_image_dcrc_valid(image_header_t *hdr)
{
	uint32_t un_crc;
	char *image_addr = (char *)hdr + sizeof(image_header_t);
	uint32_t size = ntohl(hdr->img_hdr_size);

	un_crc = 0x00000000 ^ 0xffffffff;
	un_crc = crc32(un_crc, image_addr, size);

	un_crc ^= 0xffffffff;
	return (un_crc == ntohl(hdr->img_hdr_dcrc));
}

/**=====================================================================
 * @brief  Securely validate the image
 *
 * @param nFd
 * The fd of the file that need to be validated
 *
 * @return
 *  UGW_SUCCESS on success
 *  UGW_FAILURE on failure
 =======================================================================
 */
static int fapi_ssImgValidate(img_param_t *pxImgParam, uint8_t upgradeOrCommit)
{
	int nRet = UGW_SUCCESS;
	int nSecFd = -1, boardtype;
	image_header_t *pxImgHeader = NULL;
	unsigned char *img_ptr;
	uint32_t auth_size = 0;

	if (pxImgParam->src_img_addr == NULL)
		return UGW_FAILURE;

	img_ptr = pxImgParam->src_img_addr;
	/* Open the driver device */
	nSecFd = fapi_Fileopen(SEC_UPG_PATH,
			(O_RDWR & (~O_NONBLOCK)), U_RDWR_G_RD);
	if (nSecFd < 0) {
		LOGF_LOG_ERROR("Opening Secure driver file failed.\n");
		nRet = UGW_FAILURE;
		goto failure;
	}
	pxImgHeader = (image_header_t *)img_ptr;
	if (ntohl(*(uint32_t *)img_ptr) == FLATDT_MAGIC) {
		LOGF_LOG_DEBUG(" Authenticating the FIT image, upgradeOrCommit%d\n", upgradeOrCommit);
		nRet = fapi_ssValidateDTB(nSecFd, img_ptr, upgradeOrCommit);
		close(nSecFd);
		if (nRet < 0)
			return nRet;
		return UGW_SUCCESS;
	}
	auth_size = ntohl(pxImgHeader->img_hdr_size);

	switch (pxImgHeader->img_hdr_type) {
		case IMG_HDR_VAR_KERNEL:
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), auth_size, upgradeOrCommit);
			if (nRet != UGW_SUCCESS)
				goto failure;
			LOGF_LOG_DEBUG("Kernel Image Successfully authenticated.\n");
			break;
		case IMG_HDR_VAR_FILESYSTEM:
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), (auth_size - BLW_LENGTH), upgradeOrCommit);
			if (nRet != UGW_SUCCESS)
				goto failure;
			LOGF_LOG_DEBUG("Rootfs Image Successfully authenticated.\n");
			break;
		case IMG_HDR_VAR_UBOOT:
			LOGF_LOG_DEBUG("Validating uboot image\n");
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), auth_size - BLW_LENGTH, upgradeOrCommit);
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_ERROR("uboot Image Authentication Failed!\n");
				goto failure;
			}
			LOGF_LOG_DEBUG("Uboot Image Successfully authenticated.\n");
			break;
		case IMG_HDR_VAR_MULTI:
			LOGF_LOG_DEBUG("Validating full image\n");
			nRet = fapi_ssValidateFullImage(nSecFd, pxImgParam);
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_ERROR("Full Image Authentication Failed!\n");
				goto failure;
			}
			break;
		case IMG_HDR_VAR_FIRMWARE:
			LOGF_LOG_DEBUG("Validating firmware image\n");
			if (strncmp((char *)pxImgHeader->img_hdr_name, "RBE", sizeof(pxImgHeader->img_hdr_name)) == 0)
			{
				boardtype = check_boardtype();
				if (boardtype == FLASH_TYPE_EMMC)
					img_ptr += EMMC_PAGE_SIZE + sizeof(image_header_t) + 12;
				else
					img_ptr += NAND_PAGE_SIZE + sizeof(image_header_t) + 12;
				memcpy_s(&auth_size, 4, img_ptr - 8 , 4);
				nRet = fapi_ssvalidateImg(nSecFd, img_ptr, (auth_size - 4), upgradeOrCommit);
			}
			else {
				nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), (auth_size - BLW_LENGTH), upgradeOrCommit);
			}
			if (nRet != UGW_SUCCESS) {
				LOGF_LOG_ERROR("firmware Image Authentication Failed!\n");
				goto failure;
			}
			LOGF_LOG_DEBUG("%s image Successfully authenticated.\n", pxImgHeader->img_hdr_name);
			break;
		}
	close(nSecFd);
	return UGW_SUCCESS;

failure:
	LOGF_LOG_ERROR("Verification of image failed!\n");
	close(nSecFd);
	return UGW_FAILURE;
}

static uint32_t image_multi_count(const image_header_t *hdr)
{
	uint32_t i, count = 0;
	uint32_t *size;

	/* get start of the image payload, which in case of multi
	* component images that points to a table of component sizes */
	size = (uint32_t *)((char *)hdr + sizeof(image_header_t));
	/* count non empty slots */
	for (i = 0; size[i]; ++i)
		count++;
	LOGF_LOG_DEBUG(" Multi image count=%d\n", count);

	return count;
}

static int fapi_ssvalidateImg(int nFd, void *addr, uint32_t size, uint8_t commit)
{
#ifndef LINUX_UPGRADE
	(void)commit;
#endif
	int nRet = UGW_SUCCESS;
	img_param_t xImgParam = {};
	xImgParam.src_img_addr = addr;
	xImgParam.src_img_len = size;
#ifdef LINUX_UPGRADE
	xImgParam.commit = commit;
	xImgParam.chkFARB = true;
	xImgParam.chkARB = true;
#endif
	nRet = ioctl(nFd, SS_IOC_SEC_IMGAUTH, &xImgParam);
	if (nRet != UGW_SUCCESS) {
		if (commit == false) {
			LOGF_LOG_ERROR("Image authentication ioctl failed.\n");
			return UGW_FAILURE;
		} else {
			LOGF_LOG_ERROR("Image commit ioctl failed.\n");
			return UGW_FAILURE;
		}
	}
	LOGF_LOG_DEBUG ("validate/commit success!!!\n");
	return nRet;
}

static int fapi_ssValidateDTB(int nFd, const void *addr, uint8_t upgradeOrCommit)
{
	void *data;
	char* header;
	int noffset, depth = 0;
	int nRet = 0;
	int len = 0;
	int image_size;

	noffset = fdt_path_offset(addr, FIT_IMAGES_PATH);
	if (noffset < 0) {
		LOGF_LOG_ERROR("Unable to find images within fit image\n");
		return fdt_totalsize(addr);
	}
	do {
		noffset = fdt_next_node(addr, noffset, &depth);
		if (depth < 1)
			break;
		if (upgradeOrCommit && (strcmp(fdt_get_name(addr, noffset, NULL), "device-tree") == 0)) {
			fprintf(stderr,"device-tree image, nothing to be handlled while commit operation\n");
			continue;
		} 
		if (depth == 1) {
			LOGF_LOG_DEBUG( "\nnoffset %d depth %d name %s\n", noffset, depth,
				fdt_get_name(addr, noffset, NULL));
			data = (void *)fdt_getprop(addr, noffset, FIT_DATA_PROP, &len);
			if (!len) {
				LOGF_LOG_ERROR("Unable to find dtb data\n");
				return fdt_totalsize(addr);
			}
			image_size = fdt_totalsize(addr);
			LOGF_LOG_DEBUG(" Header size %d Image size %d, image_size %d\n", SBIF_ECDSA_GetHeaderSize(
				(SBIF_ECDSA_Header_t *)data, len), getImageLen((SBIF_ECDSA_Header_t *)(data)), image_size);
			/* we authenticate only the image after the FIT headers */

			header = data;
			if (strcmp(fdt_get_name(addr, noffset, NULL), "filesystem") == 0)
				nRet = fapi_ssvalidateImg(nFd, header, len, upgradeOrCommit);
			else if(strcmp(fdt_get_name(addr, noffset, NULL), "uboot") == 0)
				nRet = fapi_ssvalidateImg(nFd, header + sizeof(image_header_t), len - sizeof(image_header_t) - BLW_LENGTH, upgradeOrCommit);
			else
				nRet = fapi_ssvalidateImg(nFd, header, len - BLW_LENGTH, upgradeOrCommit);

			if (nRet == UGW_SUCCESS) {
				nRet = image_size;
				LOGF_LOG_DEBUG("fapi_ssvalidateImg  passed for %s\n",fdt_get_name(addr, noffset, NULL));
			}
			else 
				LOGF_LOG_ERROR("\nfapi_ssvalidateImg  failed for %s\n",fdt_get_name(addr, noffset, NULL));
		}
	} while (noffset >= 0);

	return nRet;
}

static int fapi_ssValidateRootFS(int nFd, void *addr, uint32_t size)
{
	int nRet = UGW_SUCCESS;

	LOGF_LOG_DEBUG(" Sending Auth request for rootfs with  size %x\n", size);
	nRet = fapi_ssvalidateImg(nFd, addr, size, 0);
	if (nRet != UGW_SUCCESS) {
		LOGF_LOG_ERROR("Chunked Image Authentication failed.\n");
		return UGW_FAILURE;
	}
	return nRet;
}

static int fapi_ssValidateFullImage(int nSecFd, img_param_t *pxImgParam)
{
	int nRet = UGW_SUCCESS;
	uint32_t image_size;
	image_header_t *pxImgHeader = NULL;
	uint32_t pad;
	unsigned char *img_ptr = NULL;
	unsigned char *img_start_ptr = pxImgParam->src_img_addr;
	uint32_t img_len = pxImgParam->src_img_len;
	uint32_t auth_size = 0;

	do {
		img_ptr = (img_ptr ?  img_ptr + image_size : img_start_ptr);
		/* offset should start at the mkimage header */
		pxImgHeader = (image_header_t *)img_ptr;
		if (ntohl(*(uint32_t *)img_ptr) == FLATDT_MAGIC) {
			LOGF_LOG_DEBUG(" Authenticating the DTB image");
			nRet = fapi_ssValidateDTB(nSecFd, img_ptr, 0);
			if (nRet < 0)
				return nRet;
			image_size = nRet;
			continue;
		}
		/* if mkimage header is not available, exit */
		if (pxImgHeader &&
			ntohl(pxImgHeader->img_hdr_magic) != IMG_HDR_MAGIC) {
			LOGF_LOG_ERROR("no mkimage header\n");
			goto failure;
		}

		image_size = sizeof(image_header_t)
				+ ntohl(pxImgHeader->img_hdr_size);
		pad = (16 - (image_size % 16)) % 16;
		auth_size = ntohl(pxImgHeader->img_hdr_size);
		if (!is_image_hcrc_valid(pxImgHeader)) {
				printf("Bad Header Checksum\n");
			goto failure;
		}

		if (!is_image_dcrc_valid(pxImgHeader)) {
				printf("Bad Data Checksum\n");
			goto failure;
		}
		switch (pxImgHeader->img_hdr_type) {
		case IMG_HDR_VAR_MULTI:
			image_size = sizeof(image_header_t) +
					sizeof(uint32_t) *
					(image_multi_count(pxImgHeader)
					+ 1);
			continue;
		case IMG_HDR_VAR_FILESYSTEM:
			LOGF_LOG_DEBUG("authenticating rootfs of size 0x%08x...\n", image_size);
			/* removal multiimage header */
			nRet = fapi_ssValidateRootFS(nSecFd, img_ptr + sizeof(image_header_t), (auth_size - BLW_LENGTH));
			if (nRet != UGW_SUCCESS)
				goto failure;
			LOGF_LOG_DEBUG("Successfully authenitcated the Rootfs\n");
			break;
		case IMG_HDR_VAR_KERNEL:
			LOGF_LOG_DEBUG("authenticating kernel of size 0x%08x...\n", image_size);
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), auth_size, 0);
			if (nRet != UGW_SUCCESS)
				goto failure;
			LOGF_LOG_DEBUG("Kernel Image Successfully authenticated.\n");
			break;
		case IMG_HDR_VAR_FIRMWARE:
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), image_size, 0);
			if (nRet != UGW_SUCCESS)
				goto failure;
			break;
		case IMG_HDR_VAR_UBOOT:
			LOGF_LOG_DEBUG("authenticating U-boot 0x%08x...\n", image_size);
			nRet = fapi_ssvalidateImg(nSecFd, img_ptr + sizeof(image_header_t), image_size, 0);
			if (nRet != UGW_SUCCESS)
				goto failure;
			break;
		default:
			LOGF_LOG_DEBUG("Unknown image type!\n");
			image_size = image_size + BLW_LENGTH + pad;
			continue;
		}

			LOGF_LOG_DEBUG("Image size = %x pad = %x\n", image_size, pad);
			/* offset the image size to the next 16B pad */
			image_size += pad;

	} while (img_len > (img_ptr - img_start_ptr) + image_size);

	LOGF_LOG_DEBUG("Verification of fullimage Succeeded!\n");
	return UGW_SUCCESS;

failure:
	LOGF_LOG_ERROR("Verification of fullimage failed!\n");
	return UGW_FAILURE;
}
#endif

#ifdef LINUX_UPGRADE
static int fapi_ssCopyImgBPtoBP(char *dev_path, char *image_type, int boardtype, int bank)
{
	FILE *pFile;
	unsigned char *buffer;
	unsigned int lSize;
	char name[MAX_PATH_LEN] = {0};
	char *part_name;

	if ((fopen_s(&pFile, dev_path, "rb") != EOK) || !pFile) {
		LOGF_LOG_ERROR("file open failed - %s\n", strerror(errno));
		return 1;
	}

	fseek(pFile, 0, SEEK_END);
	lSize = (unsigned int)ftell (pFile);
	fseek(pFile, 0, SEEK_SET);

	buffer = (unsigned char*) malloc (lSize);

	if (buffer == NULL) {
		fputs ("Memory error",stderr);
		if (pFile != NULL)
			fclose(pFile);
		return 2;
	}

	fread (buffer,1,lSize,pFile);

	if (strcmp(image_type, "u-boot") == 0) {
		sprintf_s(name, sizeof(name), "u-boot-%s", (bank == 0 ? INACTIVE_PART_NAME : ACTIVE_PART_NAME));
		part_name = getDevFromPartition(name, 'b');
		memset(name, 0, sizeof(name));
		sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
	} else if (strcmp(image_type, "tep") == 0) {
		sprintf_s(name, sizeof(name), "tep-%s", (bank == 0 ? INACTIVE_PART_NAME : ACTIVE_PART_NAME));
		part_name = getDevFromPartition(name, 'b');
		memset(name, 0, sizeof(name));
		sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
	}else if (strcmp(image_type, "rbe") == 0) {
		if (boardtype == FLASH_TYPE_EMMC)
			sprintf_s(name, sizeof(name), "/dev/mmcblk0boot%c", (bank == 0 ? '1': '0'));
		else {
			sprintf_s(name, sizeof(name), "rbe_%c", (bank == 0 ? 'b': 'a'));
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
		}
	}
	return fapi_ssWriteToPartition(buffer, lSize, name);
}

static char *fapi_ssGetParitionNameEMMC(char *image_type, char bank)
{
	char actbnk;
	char *part_name;
	char name[MAX_PATH_LEN] = {0};
	char mnt_path[MAX_PATH_LEN] = {0};
	char cPath[MAX_PATH_LEN] = {0};
	char dev_path[MAX_PATH_LEN] = {0};
	static char file_path[MAX_PATH_LEN] = {0};
	int nRet;

	actbnk = fapi_ssCheckActiveBank();
	if ((strcmp(image_type, "kernel") == 0) || (strcmp(image_type, "rootfs") == 0))
		sprintf_s(name, sizeof(name), "kernel-%s", (actbnk == 'A' ? ACTIVE_PART_NAME : INACTIVE_PART_NAME));
	else if (strcmp(image_type, "dtb") == 0)
		sprintf_s(name, sizeof(name), "%s-%s", image_type, (actbnk == 'A' ? ACTIVE_PART_NAME : INACTIVE_PART_NAME));
	else
		sprintf_s(name, sizeof(name), "%s-%s", image_type, (bank == 'a' ? ACTIVE_PART_NAME : INACTIVE_PART_NAME));
	part_name = getDevFromPartition(name, 'b');
	sprintf_s(dev_path, MAX_PATH_LEN, "/dev/%s", part_name);
	if ((strcmp(image_type, "kernel") == 0) || (strcmp(image_type, "rootfs") == 0)) {
		sprintf_s(mnt_path, sizeof(mnt_path), "/tmp/%s", name);
		nRet = fapi_ssMountLateboot(dev_path, mnt_path);
		if (nRet != 0)
			return NULL;
		fapi_ssGetFileNameFromUboot(image_type, cPath);
		if (cPath[0] == '\0') {
			LOGF_LOG_ERROR("Error dev_path %s not valid for kernel!\n", mnt_path);
			return NULL;
		}
		sprintf_s(dev_path, sizeof(dev_path), "%s/%s", mnt_path, cPath);
	}
	strncpy_s(file_path, MAX_PATH_LEN, dev_path, MAX_PATH_LEN);

	return file_path;
}

static void fapi_ssUnmountEMMC(void)
{
	char actbnk;
	char name[MAX_PATH_LEN] = {0};
	char mnt_path[MAX_PATH_LEN] = {0};
	int nRetValue, ret;

	actbnk = fapi_ssCheckActiveBank();
	sprintf_s(name, sizeof(name), "kernel-%s", (actbnk == 'A' ? ACTIVE_PART_NAME : INACTIVE_PART_NAME));
	sprintf_s(mnt_path, sizeof(mnt_path), "/tmp/%s", name);
	if (umount(mnt_path) < 0)
		perror("umount error:");
	LOGF_LOG_DEBUG("%s unmount done!\n", mnt_path);
	sprintf_s(name, sizeof(name), "rm -rf %s\n", mnt_path);
	ret = scapi_spawn(name, 1, &nRetValue);
	if (ret == UGW_SUCCESS) {
		LOGF_LOG_DEBUG("Deleted %s!\n", mnt_path);
	} else {
		perror("mount path delete error:");
	}
}

int fapi_ssImgValidateAndCommit(char *image_type, int len)
{
#ifndef IMG_AUTH
	(void)len;
#endif
	char actbnk;
	char *part_name;
	char name[MAX_PATH_LEN] = {0};
	char *dev_path;
	int boardtype = 0, nRet = UGW_FAILURE, err, flag = 0;

	boardtype = check_boardtype();
	actbnk = fapi_ssCheckActiveBank();

	if (!(actbnk == 'A' || actbnk == 'B')) {
		LOGF_LOG_ERROR("Invalid active_bank '%c'\n", actbnk);
		return UGW_FAILURE;
	}

	err = strcmp_s(image_type, 6, "kernel", &nRet);
	if ((err == EOK) && (nRet == 0)) {
		flag = 1;
		if (boardtype == FLASH_TYPE_EMMC) {
			dev_path = fapi_ssGetParitionNameEMMC(image_type, actbnk);
			if (dev_path == NULL) {
				return UGW_FAILURE;
			}
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(dev_path, image_type, len);
#endif
			fapi_ssUnmountEMMC();
		} else {
			sprintf_s(name, sizeof(name), "kernel_%c", (actbnk == 'A' ? tolower('A'): tolower('B')));
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(name, image_type, len);
#endif
		}
	}
	if (flag == 1)
		return nRet;
	err = strcmp_s(image_type, 6, "rootfs", &nRet);
	if ((err == EOK) && (nRet == 0)) {
		flag = 1;
		if (boardtype == FLASH_TYPE_EMMC) {
			dev_path = fapi_ssGetParitionNameEMMC(image_type, actbnk);
			if (dev_path == NULL) {
				return UGW_FAILURE;
			}
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(dev_path, image_type, len);
#endif
			fapi_ssUnmountEMMC();
		} else {
			sprintf_s(name, sizeof(name), "rootfs_%c", (actbnk == 'A' ? tolower('A'): tolower('B')));
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(name, image_type, len);
#endif
		}
	}
	if (flag == 1)
		return nRet;
	err = strcmp_s(image_type, 5, "u-boot", &nRet);
	if ((err == EOK) && (nRet == 0)) {
		flag = 1;
		if (boardtype == FLASH_TYPE_EMMC) {
			dev_path = fapi_ssGetParitionNameEMMC(image_type, 'a');
			if (dev_path == NULL) {
				return UGW_FAILURE;
			}
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(dev_path, image_type, len);
			if (nRet == UGW_SUCCESS)
#endif
				nRet = fapi_ssCopyImgBPtoBP(dev_path, image_type, boardtype, 0);
		} else {
			sprintf_s(name, sizeof(name), "uboot_a");
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
#ifdef IMG_AUTH
			err = strcmp_s(image_type, 5, "uboot", &nRet);
			nRet = fapi_ssReadFromPartition(name, image_type, len);
			if (nRet == UGW_SUCCESS)
#endif
				nRet = fapi_ssCopyImgBPtoBP(name, image_type, boardtype, 0);
		}
	}

	if (flag == 1)
		return nRet;
	err = strcmp_s(image_type, 3, "tep", &nRet);
	if ((err == EOK) && (nRet == 0)) {
		flag = 1;
		if (boardtype == FLASH_TYPE_EMMC) {
			dev_path = fapi_ssGetParitionNameEMMC(image_type, 'a');
			if (dev_path == NULL) {
				return UGW_FAILURE;
			}
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(dev_path, image_type, len);
			if (nRet == UGW_SUCCESS)
#endif
				nRet = fapi_ssCopyImgBPtoBP(dev_path, image_type, boardtype, 0);
		} else {
			sprintf_s(name, sizeof(name), "tep_firmware_a");
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
#ifdef IMG_AUTH
			nRet = fapi_ssReadFromPartition(name, image_type, len);
			if (nRet == UGW_SUCCESS)
#endif
				nRet = fapi_ssCopyImgBPtoBP(name, image_type, boardtype, 0);
		}
	}

	if (flag == 1)
		return nRet;
	err = strcmp_s(image_type, 3, "rbe", &nRet);
	if ((err == EOK) && (nRet == 0)) {
		flag = 1;
		if (boardtype == FLASH_TYPE_EMMC) {
			sprintf_s(name, MAX_PATH_LEN, "/dev/mmcblk0boot0");
		} else {
			sprintf_s(name, sizeof(name), "rbe_a");
			part_name = getDevFromPartition(name, 'b');
			memset(name, 0, sizeof(name));
			sprintf_s(name, MAX_PATH_LEN, "/dev/%s", part_name);
		}
#ifdef IMG_AUTH
		nRet = fapi_ssReadFromPartition(name, image_type, len);
		if (nRet == UGW_SUCCESS)
#endif
			nRet = fapi_ssCopyImgBPtoBP(name, image_type, boardtype, 0);
	}
	return nRet;
}
#endif

/**=================================================================
 * @brief  validate the state input
 *
 * @param pcState
 * upgrade state variable
 *
 * @return
 *  current state enum value on success
 *  UGW_FAILURE on failure
 ===================================================================
 */
static State_t fapi_ssValidateState(unsigned char *pcState)
{
	int nCnt = 0;
	State_t eRes = UPG_NONE;

	for (nCnt = 0; nCnt < MAX_STATE_CNT; ++nCnt, ++eRes) {
		if (0 == strcmp((char *)pcState, (char *)sState[nCnt]))
			return eRes;
	}
	return MAX_STATE_CNT;
}

/**===================================================================
 * @brief  get upgrade status
 *
 * @param pcState
 * upgrade state variable
 *
 * @return
 *  current state on success
 *  UGW_FAILURE on failure
 =====================================================================
 */
int fapi_ssGetUpgState(unsigned char **pcState)
{
	int nFd = -1, nRet = UGW_SUCCESS, nEn = -1;
	char sBuf[MAX_WRITE] = {0};
	struct flock fl = {};

	nFd = fapi_Fileopen(UPG_STATE_FILE, O_RDONLY, 0);
	if (nFd  < 0) {
		LOGF_LOG_ERROR("open failed for %s\n", UPG_STATE_FILE);
		return UGW_FAILURE;
	}

	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(nFd, F_SETLKW, &fl) == -1) {
		LOGF_LOG_ERROR("file lock failed\n");
		nRet = UGW_FAILURE;
		goto finish;
	}

	if (read(nFd, sBuf, MAX_WRITE-1) < 0) {
		LOGF_LOG_ERROR("read state variable failed\n");
		nRet = UGW_FAILURE;
		goto next;
	}

	nEn = atoi(sBuf);

	if (nEn == UPG_NONE)
		*pcState = sState[UPG_NONE];
	else if (nEn == UPG_REQ)
		*pcState = sState[UPG_REQ];
	else if (nEn == UPG_INPROG)
		*pcState = sState[UPG_INPROG];
	else if (nEn == UPG_SUCC)
		*pcState = sState[UPG_SUCC];
	else if (nEn == UPG_FAIL)
		*pcState = sState[UPG_FAIL];
	else
		*pcState = 0;

next:
	fl.l_type = F_UNLCK;

	if (fcntl(nFd, F_SETLK, &fl) == -1)
		LOGF_LOG_ERROR("file unlock failed\n");

finish:
	if (nFd >= 0)
		close(nFd);

	return nRet;
}

/**============================================================
 * @brief  set upgrade status
 *
 * @param pcState
 * upgrade state variable
 *
 * @return
 *  current state on success
 *  UGW_FAILURE on failure
 ==============================================================
 */
int fapi_ssSetUpgState(unsigned char *pcState)
{
	int nFd = -1, nRet = UGW_SUCCESS;
	State_t eRes;
	char sBuf[MAX_WRITE] = {0};
	struct flock fl = {};

	eRes = fapi_ssValidateState(pcState);
	if (eRes == MAX_STATE_CNT) {
		LOGF_LOG_ERROR("invalid state value(%s) set request\n", pcState);
		return UGW_FAILURE;
	}

	nFd = fapi_Fileopen(UPG_STATE_FILE, O_RDWR, U_RDWR_G_RD);
	if (nFd  < 0) {
		LOGF_LOG_ERROR("open failed for %s\n", UPG_STATE_FILE);
		return UGW_FAILURE;
	}

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 0;
	fl.l_len = 0;

	if (fcntl(nFd, F_SETLKW, &fl) == -1) {
		LOGF_LOG_ERROR("file lock failed\n");
		nRet = UGW_FAILURE;
		goto finish;
	}

	sprintf_s(sBuf, MAX_WRITE, "%d", eRes);
	if (write(nFd, sBuf, MAX_WRITE) < 0) {
		LOGF_LOG_ERROR("updating state variable failed\n");
		nRet = UGW_FAILURE;
	}

	fl.l_type = F_UNLCK;

	if (fcntl(nFd, F_SETLK, &fl) == -1) {
		LOGF_LOG_ERROR("file unlock failed\n");
		nRet = UGW_FAILURE;
	}

finish:
	if (nFd >= 0)
		close(nFd);

	return nRet;
}

#ifdef LINUX_UPGRADE
#ifdef IMG_AUTH
static int fapi_ssReadFromPartition(char *dev_path, char* type, long unsigned int len)
{
	FILE *pFile;
	unsigned int lSize;
	char *buffer;
	int ret = 0;
	int nSecFd = -1, boardtype;
	image_header_t x_img_header;
	uint32_t auth_size = 0;

	if ((fopen_s(&pFile, dev_path, "rb") != EOK) || !pFile) {
		LOGF_LOG_ERROR("File open failed - %s\n", strerror(errno));
		return UGW_FAILURE;
	}
	fseek (pFile, 0, SEEK_END);
	lSize = (unsigned int)ftell (pFile);
	fseek(pFile, 0, SEEK_SET);

	/* Open the driver device */
	nSecFd = fapi_Fileopen(SEC_UPG_PATH,
			(O_RDWR & (~O_NONBLOCK)), U_RDWR_G_RD);
	if (nSecFd < 0) {
		LOGF_LOG_ERROR("Opening Secure driver file failed.\n");
		fclose(pFile);
		return ret;
	}

	buffer = (char*) malloc (lSize);
	if (buffer == NULL) {
		fputs ("Memory error",stderr);
		close(nSecFd);
		if (pFile != NULL)
			fclose(pFile);
		return UGW_FAILURE;
	}
	boardtype = check_boardtype();

	/* copy the file into the buffer */
	fread (buffer,1,lSize,pFile);

	x_img_header = *((image_header_t *)buffer);

	if (ntohl(*(uint32_t *)buffer) == FLATDT_MAGIC) {
		LOGF_LOG_DEBUG(" Authenticating the image with upgradeOrCommit value 1\n");
		ret = fapi_ssValidateDTB(nSecFd, buffer, 1);
		close(nSecFd);
		free(buffer);
		fclose(pFile);
		if (ret < 0)
			return ret;
		return UGW_SUCCESS;
	}

	if (strcmp(type,"kernel") == 0) {
		if (boardtype == FLASH_TYPE_EMMC)
			ret = fapi_ssvalidateImg(nSecFd, buffer + sizeof(image_header_t), ntohl(x_img_header.img_hdr_size), 1);
		else
			ret = fapi_ssvalidateImg(nSecFd, buffer + sizeof(image_header_t), ntohl(x_img_header.img_hdr_size) - sizeof(image_header_t), 1);
	} else if (strcmp(type,"rootfs") == 0) {
		if (ret == 0) {
			if (boardtype == FLASH_TYPE_EMMC)
				ret = fapi_ssvalidateImg(nSecFd, buffer, len - BLW_LENGTH, 1);
			else
				ret = fapi_ssvalidateImg(nSecFd, buffer , len + sizeof(image_header_t) - BLW_LENGTH, 1);
		}
	} else if (strcmp(type,"tep_firmware") == 0) {
		if (ret == 0) {
			ret = fapi_ssvalidateImg(nSecFd, buffer , len - BLW_LENGTH , 1);
		}
	} else if (strcmp(type,"rbe") == 0) {
		if (ret == 0) {
			if (boardtype == FLASH_TYPE_EMMC) {
				memcpy_s(&auth_size, 4, buffer + EMMC_PAGE_SIZE + 12 - BLW_LENGTH , 4);
				ret = fapi_ssvalidateImg(nSecFd, buffer + EMMC_PAGE_SIZE +12 , auth_size - 4, 1);
			} else {
				memcpy_s(&auth_size, 4, buffer + NAND_PAGE_SIZE + 12 - BLW_LENGTH , 4);
				ret = fapi_ssvalidateImg(nSecFd, buffer + NAND_PAGE_SIZE +12 , auth_size - 4, 1);
			}
		}
	} else if (strcmp(type,"uboot") == 0) {
		if (ret == 0) {
			ret = fapi_ssvalidateImg(nSecFd, buffer + sizeof(image_header_t), ntohl(x_img_header.img_hdr_size) - BLW_LENGTH, 1);
		}
	} else {
		if (ret == 0) {
			ret = fapi_ssvalidateImg(nSecFd, buffer , len - BLW_LENGTH, 1);
		}
	}

	close(nSecFd);
	free(buffer);
	fclose(pFile);
	if (ret != UGW_SUCCESS)
			return UGW_FAILURE;
	LOGF_LOG_DEBUG(" Image Successfully commited.\n");
	return ret;
}
#endif
static int fapi_ssWriteToPartition(const unsigned char *image_src_address, int image_len, char *dev_path)
{
	FILE *fp1 = NULL;
	int flag = 0;

	if (strncmp(dev_path, "/dev/mmcblk0boot0", MAX_PATH_LEN) == 0)
		system("/bin/echo 0 > /sys/block/mmcblk0boot0/force_ro");
	else if	(strncmp(dev_path, "/dev/mmcblk0boot1", MAX_PATH_LEN) == 0)
		system("/bin/echo 0 > /sys/block/mmcblk0boot1/force_ro");

	if (fopen_s(&fp1, dev_path, "w") != EOK) {
		LOGF_LOG_ERROR("Error %s!\n", strerror(errno));
		return UGW_FAILURE;
	}
	if (fp1 == NULL) {
		LOGF_LOG_ERROR("File pointer is NULL!\n");
		return UGW_FAILURE;
	}

	flag = fwrite(image_src_address, image_len, 1, fp1);
	if (flag) {
		LOGF_LOG_DEBUG("Contents of the structure written successfully\n");
	} else {
		LOGF_LOG_ERROR("Error Writing to File!\n");
	}

	fclose(fp1);
	if (strncmp(dev_path, "/dev/mmcblk0boot0", MAX_PATH_LEN) == 0)
		system("/bin/echo 1 > /sys/block/mmcblk0boot0/force_ro");
	else if	(strncmp(dev_path, "/dev/mmcblk0boot1", MAX_PATH_LEN) == 0)
		system("/bin/echo 1 > /sys/block/mmcblk0boot1/force_ro");
	return UGW_SUCCESS;
}

static int fapi_ssMountLateboot(char *mnt_part, char *mnt_path)
{
	char param[MAX_PATH_LEN] = {0};
	int nRetValue, ret;

	LOGF_LOG_DEBUG("mnt_part: %s, mnt_path: %s\n", mnt_part, mnt_path);
	sprintf_s(param, sizeof(param), "mkdir -p %s\n", mnt_path);
	ret = scapi_spawn(param, 1, &nRetValue);

	if (ret == UGW_SUCCESS) {
		sprintf_s(param, sizeof(param), "mount -t ext4 %s %s/\n", mnt_part, mnt_path);
		ret = scapi_spawn(param, 1, &nRetValue);
		if (nRetValue != UGW_SUCCESS){
			sprintf_s(param, sizeof(param), "resize2fs %s && mount -t ext4 %s %s/\n", mnt_part, mnt_part, mnt_path);
			printf("\ntrying resize2fs and mount again : %s\n",param);
			return scapi_spawn(param, 1, &nRetValue);
		}
	}
	return ret;
}

static char fapi_ssCheckActiveBank(void)
{
	FILE *output = NULL;
	char sActBnk;

	output = popen("uboot_env --get --name active_bank", "r");
	if (output == NULL) {
		LOGF_LOG_ERROR("Error launching the cmd to get active_bank the uboot environment\n");
		return UGW_SUCCESS;
	}
	if (fread(&sActBnk, 1, sizeof(sActBnk), output) > 0) {
		pclose(output);
		return sActBnk;
	} else {
		LOGF_LOG_ERROR("variable not found in uboot\n");
		pclose(output);
		return UGW_SUCCESS;
	}
}

static void fapi_ssGetFileNameFromUboot(char *file_name, char *cPath)
{
	FILE *output;
	char name[MAX_PATH_LEN] = {0};
	char cmd[MAX_PATH_LEN] = {0};
	int len;

	if (strncmp(file_name, "kernel", sizeof("kernel")) == 0)
		sprintf_s(cmd, sizeof(cmd), "uboot_env --get --name bootfile");
	else
		sprintf_s(cmd, sizeof(cmd), "uboot_env --get --name %s", file_name);

	output = popen(cmd, "r");
	if (output == NULL) {
		LOGF_LOG_ERROR("Error launching the cmd to get active_bank the uboot environment\n");
		return;
	}
	len = fread(&name, sizeof(char), MAX_PATH_LEN - 1, output);
	if (len > 0) {
		pclose(output);
		strncpy_s(cPath, MAX_PATH_LEN, name, MAX_PATH_LEN);
		while (len && (cPath[len - 1] == '\n' || cPath[len - 1] == '\r'))
			cPath[--len] = 0;
	} else {
		LOGF_LOG_ERROR("variable not found in uboot\n");
		pclose(output);
	}
}

static int fapi_ssCheckFileSize(img_param_t image_auth)
{
	int i = 0, nRet=UGW_FAILURE;
	char actbnk;
	char name[MAX_PATH_LEN] = {0};
	char dev_path[MAX_PATH_LEN] = {0};
	char *part_name = NULL;
	int boardtype;
	FILE *fp1 = NULL;
	unsigned int lSize;
	int noffset, depth = 0;
	int len = 0;

	actbnk = fapi_ssCheckActiveBank();
	if (!(actbnk == 'A' || actbnk == 'B')) {
		LOGF_LOG_ERROR("Invalid active_bank '%c'\n", actbnk);
		nRet = UGW_FAILURE;
		goto finish;
	}

	boardtype = check_boardtype();
	if (boardtype < 0) {
		LOGF_LOG_ERROR("invalid board type\n");
		nRet = UGW_FAILURE;
		goto finish;
	}
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (strncmp(image_auth.img_name, map[i].name, sizeof(image_auth.img_name)) != 0) 
			continue;

		memset(dev_path, 0, sizeof(dev_path));
		if (map[i].early_boot == true) {
			/* Early boot component always written in primary bank */
			if ((strncmp(map[i].name, "rbe", sizeof(image_auth.img_name)) == 0) && (boardtype == FLASH_TYPE_EMMC))
				sprintf_s(dev_path, sizeof(dev_path), "/dev/mmcblk0boot0");
			else
				sprintf_s(name, sizeof(name), "%s-%s", map[i].part,ACTIVE_PART_NAME);
		} else {
			/* Late boot component always written in non-active bank */
			if (boardtype == FLASH_TYPE_EMMC) {
				sprintf_s(name, sizeof(name), "%s-%s", map[i].part, (actbnk == 'A' ? INACTIVE_PART_NAME : ACTIVE_PART_NAME));
			} else {
				/* for NAND model partition name like roofs_*, kernel_* and dtb_* */
				if (strncmp(image_auth.img_name, "rootfs", sizeof(image_auth.img_name)) == 0)
					sprintf_s(name, sizeof(name), "rootfs_%c", (actbnk == 'A' ? tolower('B'): tolower('A')));
				else if (strncmp(image_auth.img_name, "kernel", sizeof(image_auth.img_name)) == 0)
					sprintf_s(name, sizeof(name), "kernel_%c", (actbnk == 'A' ? tolower('B'): tolower('A')));
				else
					sprintf_s(name, sizeof(name), "%s_%c", map[i].part, (actbnk == 'A' ? tolower('B'): tolower('A')));
			}
		}
		if (dev_path[0] == '\0') {
			part_name = getDevFromPartition(name, 'b');
			sprintf_s(dev_path, sizeof(dev_path), "/dev/%s", part_name);
		}
		if ((fopen_s(&fp1, dev_path, "rb") != EOK) || !fp1) {
			LOGF_LOG_ERROR("File error - %s\n", strerror(errno));
			nRet = UGW_FAILURE;
			goto finish;
		}
		fseek (fp1, 0, SEEK_END);
		lSize = (unsigned int)ftell (fp1);
		fseek(fp1, 0, SEEK_SET);
		fclose(fp1);
		if (strncmp(map[i].name, "dtb", sizeof(map[i].name)) != 0) { 
			if ((unsigned int)image_auth.src_img_len > lSize) {
				LOGF_LOG_ERROR("Given %s image length(%lu) is greater than partition lenth(%u)!\n", map[i].name, image_auth.src_img_len, lSize);
				nRet = UGW_FAILURE;
				goto finish;
			} else {
				LOGF_LOG_DEBUG("Given %s image size is less than partition!\n", map[i].name);
				nRet = UGW_SUCCESS;
			}
		} else if((strncmp(map[i].name, "kernel-dtb", sizeof(map[i].name)) == 0) ||
		        (strncmp(map[i].name, "filesystem", sizeof(map[i].name)) == 0)) {
			image_auth.src_img_len = fdt_totalsize(image_auth.src_img_addr);
			if (image_auth.src_img_len > lSize) {
				LOGF_LOG_ERROR("Given %s image length(%lu) is greater than partition lenth(%u)!\n", map[i].name, image_auth.src_img_len, lSize);
				nRet = UGW_FAILURE;
				goto finish;
			} else {
				LOGF_LOG_DEBUG("Given %s image size (%lu) is less than partition size %u!\n", map[i].name, image_auth.src_img_len, lSize);
				return image_auth.src_img_len;
			} 
			
 		} else {
			noffset = fdt_path_offset(image_auth.src_img_addr, FIT_IMAGES_PATH);
			if (noffset < 0) {
				fprintf(stderr,"Unable to find dtb within fit image\n");
				return UGW_FAILURE;
			}

			do {
				noffset = fdt_next_node(image_auth.src_img_addr, noffset, &depth);
				LOGF_LOG_DEBUG("noffset %d depth %d name %s\n", noffset, depth,
					fdt_get_name(image_auth.src_img_addr, noffset, NULL));
				if (depth == 1)
					break;
			} while (noffset >= 0);

			if (noffset < 0) {
				LOGF_LOG_ERROR("Unable to find dtb within fit image\n");
				return UGW_FAILURE;
			}

			(void)fdt_getprop(image_auth.src_img_addr, noffset, FIT_DATA_PROP, &len);
			if (!len) {
				LOGF_LOG_ERROR("Unable to find dtb data\n");
				return UGW_FAILURE;
			}
			if ((unsigned int)len > lSize) {
				LOGF_LOG_ERROR("Given %s image length(%lu) is greater than partition lenth(%u)!\n", map[i].name, image_auth.src_img_len, lSize);
				nRet = UGW_FAILURE;
				goto finish;
			} else {
				LOGF_LOG_DEBUG("Given %s image size (%d) is less than partition size %u!\n", map[i].name, len, lSize);
				return fdt_totalsize(image_auth.src_img_addr);
			}
		}
	}
finish:
	return nRet;
}

static int fapi_ssWriteToDtbPartition(img_param_t image_auth, char *name)
{
	const void *data;
	int noffset, depth = 0;
	int len = 0, ret = 0;

	noffset = fdt_path_offset(image_auth.src_img_addr, FIT_IMAGES_PATH);
	do {
		noffset = fdt_next_node(image_auth.src_img_addr, noffset, &depth);
		LOGF_LOG_DEBUG("noffset %d depth %d name %s\n", noffset, depth,
				fdt_get_name(image_auth.src_img_addr, noffset, NULL));
		if (depth == 1)
			break;
	} while (noffset >= 0);

	if (noffset < 0) {
		LOGF_LOG_ERROR("Unable to find dtb within fit image\n");
		return fdt_totalsize(image_auth.src_img_addr);
	}

	data = fdt_getprop(image_auth.src_img_addr, noffset, FIT_DATA_PROP, &len);
	if (!len) {
		LOGF_LOG_ERROR("Unable to find dtb data\n");
		return fdt_totalsize(image_auth.src_img_addr);
	}
	LOGF_LOG_DEBUG("dtb image dev_path: %s\n", name);
	ret = fapi_ssWriteToPartition(data, len, name);
	if (ret == UGW_SUCCESS)
		ret = fdt_totalsize(image_auth.src_img_addr);

	return ret;
}
int fapi_ssImgUpgrade(img_param_t image_auth)
{
	int i = 0, nRet = UGW_FAILURE;
	char actbnk;
	char name[MAX_PATH_LEN] = {0};
	char dev_path[MAX_PATH_LEN] = {0};
	char mnt_path[MAX_PATH_LEN] = {0};
	char *part_name = NULL;
	char cPath[MAX_PATH_LEN] = {0};
	int boardtype;
	int nLockFd = -1, nRetValue;

	nLockFd = fapi_Fileopen(LOCK_FILE, O_RDONLY, 0);
	if (nLockFd < 0) {
		LOGF_LOG_ERROR("LOCK FILE open failed [%s]\n", strerror(errno));
		return UGW_FAILURE;
	}

	if (flock(nLockFd, LOCK_EX) < 0) {
		LOGF_LOG_ERROR("flock failed with reason [%s]\n", strerror(errno));
		if (close(nLockFd) < 0)
			LOGF_LOG_DEBUG("close failed with reason [%s]\n", strerror(errno));
		return UGW_FAILURE;
	}

	if (image_auth.src_img_fd < 0) {
		LOGF_LOG_ERROR("image_auth.src_img_fd is less than 0\n");
		nRet = ERR_BAD_FD;
		goto finish;
	}
	actbnk = fapi_ssCheckActiveBank();
	if (!(actbnk == 'A' || actbnk == 'B')) {
		LOGF_LOG_ERROR("Invalid active_bank '%c'\n", actbnk);
		nRet = UGW_FAILURE;
		goto finish;
	}
	for (i = 0; i < ARRAY_SIZE(map); i++) {
		if (strncmp(image_auth.img_name, map[i].name, sizeof(image_auth.img_name)) != 0) 
			continue;

		boardtype = check_boardtype();
		memset(dev_path, 0, sizeof(dev_path));
		if (map[i].early_boot == true) {
			/* Early boot component always written in primary bank */
			if ((strncmp(map[i].name, "rbe", sizeof(image_auth.img_name)) == 0) && (boardtype == FLASH_TYPE_EMMC))
				sprintf_s(dev_path, sizeof(dev_path), "/dev/mmcblk0boot0");
			else
				sprintf_s(name, sizeof(name), "%s-%s", map[i].part,ACTIVE_PART_NAME);
		} else {
			/* Late boot component always written in non-active bank */
			if (boardtype == FLASH_TYPE_EMMC) {
				sprintf_s(name, sizeof(name), "%s-%s", map[i].part, (actbnk == 'A' ? INACTIVE_PART_NAME : ACTIVE_PART_NAME));
			} else {
				/* for NAND model partition name like roofs_*, kernel_* and dtb_* */
				if (strncmp(image_auth.img_name, "rootfs", sizeof(image_auth.img_name)) == 0)
					sprintf_s(name, sizeof(name), "rootfs_%c", (actbnk == 'A' ? tolower('B'): tolower('A')));
				else if (strncmp(image_auth.img_name, "kernel", sizeof(image_auth.img_name)) == 0)
					sprintf_s(name, sizeof(name), "kernel_%c", (actbnk == 'A' ? tolower('B'): tolower('A')));
				else
					sprintf_s(name, sizeof(name), "%s_%c", map[i].part, (actbnk == 'A' ? tolower('B'): tolower('A')));
			}
		}
		if (dev_path[0] == '\0') {
			part_name = getDevFromPartition(name, 'b');
			sprintf_s(dev_path, sizeof(dev_path), "/dev/%s", part_name);
		}
		/* For EMMC rootfs and kernel mount is needed */
		if (boardtype == FLASH_TYPE_EMMC) {
			if ((strncmp(map[i].name, "rootfs", sizeof(map[i].name)) == 0) ||
				(strncmp(map[i].name, "kernel", sizeof(map[i].name)) == 0)) {
				sprintf_s(mnt_path, sizeof(mnt_path), "/tmp/%s", name);
				fprintf(stdout,"mnt_path %s dev_path %s\n", mnt_path, dev_path);
				nRet = fapi_ssMountLateboot(dev_path, mnt_path);
				if (nRet != UGW_SUCCESS) {
					LOGF_LOG_DEBUG("already mounted\n");
				} else {
					LOGF_LOG_DEBUG("mount success\n");
				}
				memset(dev_path, 0, sizeof(dev_path));
				fapi_ssGetFileNameFromUboot(map[i].name, cPath);
				if (cPath[0] == '\0') {
					LOGF_LOG_ERROR("Error dev_path %s not valid for kernel!\n", mnt_path);
					nRet = UGW_FAILURE;
					goto finish;
				}
				sprintf_s(dev_path, sizeof(dev_path), "%s/%s", mnt_path, cPath);
			}
		}
		if (strncmp(map[i].name, "dtb", sizeof(map[i].name)) == 0) {
			nRet = fapi_ssWriteToDtbPartition(image_auth, dev_path);
			goto finish;
		} else {
			LOGF_LOG_DEBUG("image is :%s and dev_path: %s\n", map[i].name, dev_path);
			nRet = fapi_ssWriteToPartition(image_auth.src_img_addr, image_auth.src_img_len, dev_path);
			if (boardtype == 1) {
				if ((strncmp(map[i].name, "rootfs", sizeof(map[i].name)) == 0) ||
					(strncmp(map[i].name, "kernel", sizeof(map[i].name)) == 0)) {
					if (umount(mnt_path) < 0) {
						perror("umount error:");
					} else {
						sprintf_s(name, sizeof(name), "rm -rf %s\n", mnt_path);
						nRet = scapi_spawn(name, 1, &nRetValue);
						if (nRet == UGW_SUCCESS) {
							LOGF_LOG_DEBUG("Deleted %s!\n", mnt_path);
						} else {
							perror("mount path delete error:");
						}
					}
				}
			}
			goto finish;
		}
	}
finish:
	if (flock(nLockFd, LOCK_UN) < 0)
		LOGF_LOG_DEBUG("unlock failed with reason [%s]\n",
		strerror(errno));

	if (close(nLockFd) < 0)
		LOGF_LOG_DEBUG("close failed with reason [%s]\n",
		strerror(errno));

	return nRet;
}
#else
int fapi_ssWriteToUpgPartition(img_param_t *pxImg)
{
	int nFd, nRetValue;
	size_t nLen = 0, nChar;
	char param[512], *tempfilename = NULL;
	struct stat filestat = {0};
	int nRet = UGW_SUCCESS;
	int boardtype;
	bool validcontent = false;
	char *pathname = NULL, buf[30], mmcdev[20];
	FILE *fp1 = NULL, *fp2 = NULL;

	/* Check for the filename */
	if (!pxImg->img_name || !strnlen_s(pxImg->img_name, MAX_FILE_NAME)) {
		LOGF_LOG_ERROR("File name is missing!\n");
		return UGW_FAILURE;
	}
	sprintf_s(param, sizeof(param), "/mnt/upgrade");
	if (stat(param, &filestat) < 0) {
		if ((mkdir("/mnt/upgrade", 0766)) < 0) {
			LOGF_LOG_ERROR("Error creating the /mnt/upgrade directory!\n");
			return UGW_FAILURE;
		}
	}
	boardtype = check_boardtype();
	if (boardtype == FLASH_TYPE_EMMC) {
		tempfilename = tempnam("/tmp", NULL);
		LOGF_LOG_DEBUG("filename %s\n", tempfilename);

		if (!tempfilename) {
			LOGF_LOG_ERROR("Error creating tempfile name!\n");
			return UGW_FAILURE;
		}

		sprintf_s(param, sizeof(param), "/bin/grep -rl upgrade_partition /sys/class/block/mmcblk0p*/uevent > %s", tempfilename);

		nRet = scapi_spawn(param, 1, &nRetValue);
		if (nRet != UGW_SUCCESS || nRetValue > 0) {
			LOGF_LOG_ERROR("Error in identifying upgrade partition!\n");
			remove(tempfilename);
			return UGW_FAILURE;
		}

		if (fopen_s(&fp1, tempfilename, "r") != EOK) {
			LOGF_LOG_ERROR("Error %s!\n", strerror(errno));
			remove(tempfilename);
			return UGW_FAILURE;
		}

		if (fp1 != NULL) {
			nChar = getline(&pathname, &nLen, fp1);
			if (pathname == NULL || nChar <= 0) {
				LOGF_LOG_ERROR("File Empty");
				nRet = UGW_FAILURE;
				goto failure;
			} else {
				if (pathname[nChar - 1] == '\n') {
					if (--nChar == 0) {
						nRet=UGW_FAILURE;
						goto failure;
					}
					pathname[nChar] = '\0';
				}
			}
			LOGF_LOG_DEBUG("path name is %s", pathname);
			if (pathname != NULL) {
				if (fopen_s(&fp2, pathname, "r") != EOK || !fp2) {
					LOGF_LOG_ERROR("Error %s!\n", strerror(errno));
					nRet = UGW_FAILURE;
					goto failure;
				}

				while (fgets(buf, 30, fp2) != NULL) {
					if (strstr(buf, "PARTNAME=upgrade_partition")) {
						LOGF_LOG_DEBUG("PARTNAME is valid\n");
						validcontent = 1;
					}
					if (strstr(buf, "DEVNAME=")) {
						nLen = strlcpy(mmcdev, &buf[8], sizeof(mmcdev));
						if (nLen > 0) {
							if ((mmcdev)[nLen - 1] == '\n') {
								(mmcdev)[nLen - 1] = '\0';
								--nLen;
							}
						} else {
							LOGF_LOG_ERROR("file improper\n");
							nRet = UGW_FAILURE;
							goto failure;
						}
					}
				}
				if (validcontent) {
					LOGF_LOG_DEBUG("DEVNAME is %s\n", mmcdev);
				} else {
					LOGF_LOG_ERROR("file improper\n");
					nRet = UGW_FAILURE;
					goto failure;
				}
			}

			/*umount the upgrade partition if mounted*/
			sprintf_s(param, sizeof(param), "umount /dev/%s", mmcdev);
			nRet = scapi_spawn(param, 1, &nRetValue);
			if (nRet != UGW_SUCCESS)
				return UGW_FAILURE;

			/*format the upgrade partition*/
			sprintf_s(param, sizeof(param), "mkfs.ext2 -F /dev/%s", mmcdev);
			nRet = scapi_spawn(param, 1, &nRetValue);
			if (nRet != UGW_SUCCESS)
				return UGW_FAILURE;
		} else {
			printf("failed to get the upgrade dev\n");
			return UGW_FAILURE;
		}

		sprintf_s(param, sizeof(param), "/dev/%s", mmcdev);
		if (mount(param, "/mnt/upgrade", "ext4", MS_MGC_VAL, NULL) < 0) {
			perror("mount error:");
			return UGW_FAILURE;
		}
		if (chown("/tmp/mount_upgrade", 13, 54) < 0) {
			perror("chown error:");
			return UGW_FAILURE;
		}
		if (chmod("/tmp/mount_upgrade", 0770) < 0) {
			perror("chmod error:");
			return UGW_FAILURE;
		}
	} else if (boardtype == FLASH_TYPE_NAND) {
		if (mount(UPGRADE_PARTITION_NAND, "/mnt/upgrade", "ubifs", MS_MGC_VAL, NULL) < 0) {
			LOGF_LOG_ERROR("Error mounting the upgrade partition!\n");
			return UGW_FAILURE;
		}
	} else {
		LOGF_LOG_ERROR("Unknown LGM board!\n");
		return UGW_FAILURE;
	}

	sprintf_s(param, sizeof(param), "/mnt/upgrade/%s", pxImg->img_name);
	if (stat(param, &filestat) == 0) {
		LOGF_LOG_ERROR("File exists...deleting it!\n");
		if (remove(param)) {
			LOGF_LOG_ERROR("Error deleting the file!\n");
			nRet = UGW_FAILURE;
			goto failure;
		}
	}

	printf("trying opening the filein /mnt/upgrade/%s!\n", pxImg->img_name);
	sprintf_s(param, sizeof(param), "/mnt/upgrade/%s", pxImg->img_name);
	nFd = open(param, O_RDWR | O_CREAT);
	if (nFd < 0) {
		LOGF_LOG_ERROR("Error opening the file!\n");
		nRet = UGW_FAILURE;
		goto failure;
	}
	printf("writing %s to upgrade parttion!\n",pxImg->img_name);
	nLen = write(nFd, pxImg->src_img_addr, pxImg->src_img_len);
	if (nLen != pxImg->src_img_len) {
		LOGF_LOG_ERROR("Error writing to upgrade parttion!\n");
		close(nFd);
		nRet = UGW_FAILURE;
		goto failure;
	}
	close(nFd);
failure:
	if (umount("/mnt/upgrade") < 0)
		perror("umount error:");
	if (tempfilename)
		remove(tempfilename);
	if (fp1)
		fclose(fp1);
	if (fp2)
		fclose(fp2);
	free(pathname);
	return nRet;
}
#endif

/**=====================================================================
 * @brief  Securely validate the image.
 *
 * @param image_auth
 * structure to validate the image
 *
 * @return
 *  UGW_SUCCESS on success
 *  UGW_FAILURE on failure
 =======================================================================
 */

int fapi_ssImgAuth(img_param_t image_auth)
{
	int nRet = UGW_SUCCESS;
#ifndef LINUX_UPGRADE
	unsigned char *pcState = NULL;
#endif
	int nLockFd = -1;

	nLockFd = fapi_Fileopen(LOCK_FILE, O_RDONLY, 0);
	if (nLockFd < 0) {
		LOGF_LOG_ERROR("LOCK FILE open failed [%s]\n", strerror(errno));
		return UGW_FAILURE;
	}

	if (flock(nLockFd, LOCK_EX) < 0) {
		LOGF_LOG_ERROR("flock failed with reason [%s]\n", strerror(errno));
		if (close(nLockFd) < 0)
			LOGF_LOG_DEBUG("close failed with reason [%s]\n", strerror(errno));
		return UGW_FAILURE;
	}

	if (image_auth.src_img_fd < 0) {
		LOGF_LOG_ERROR("image_auth.src_img_fd is less than 0\n");
		nRet = ERR_BAD_FD;
		goto finish;
	}

#ifndef LINUX_UPGRADE
	nRet = fapi_ssGetUpgState(&pcState);
	if (nRet == UGW_FAILURE) {
		LOGF_LOG_ERROR("State variable retrieval failed\n");
		nRet = UGW_FAILURE;
		goto finish;
	}

	if (pcState == NULL) {
		nRet = UGW_FAILURE;
		goto finish;
	} else if ((strcmp((char *)pcState, (char *)sState[UPG_REQ]) == 0) || (strcmp((char *)pcState, (char *)sState[UPG_INPROG]) == 0)) {
		LOGF_LOG_ERROR("Upgrade in progress, wait until previous upgrade completes\n");
		nRet = IMAGE_UPGSTATE_ERROR;
		goto finish;
	} else{
		nRet = fapi_ssSetUpgState(sState[UPG_REQ]);
		if (nRet == UGW_FAILURE)
			goto finish;

		/* perform validation
			1. image header valiation
			2. secure image valiation on 4kec side
		*/
#endif
#ifdef IMG_AUTH
		nRet = fapi_ssImgValidate(&image_auth, 0);
#endif
		if (nRet == UGW_SUCCESS) {
#ifdef LINUX_UPGRADE
				nRet = fapi_ssCheckFileSize(image_auth);
				if (nRet < 0) {
					LOGF_LOG_ERROR("Image validation failed\n");
					goto finish;
				}
#else
			/* check if we need to write the imaeg to the upgrade partition*/
			if (image_auth.write_to_upg_part) {
				nRet = fapi_ssWriteToUpgPartition(&image_auth);
				if (nRet < 0) {
					LOGF_LOG_ERROR("writing to upg partition failed\n");
					nRet = IMAGE_WRITE_FAILED;
					goto finish;
				}
			}
			if (fapi_ssSetUpgState(sState[UPG_INPROG]) == UGW_FAILURE) {
				LOGF_LOG_ERROR("state variable success case update failed\n");
				nRet = IMAGE_UPGSTATE_ERROR;
			}
#endif
#ifndef LINUX_UPGRADE
		} else{
			if (fapi_ssSetUpgState(sState[UPG_FAIL]) ==
				UGW_FAILURE) {
				LOGF_LOG_ERROR
				("state variable failure case update failed\n");
				nRet = IMAGE_UPGSTATE_ERROR;
			} else {
				nRet = IMAGE_VALIDATION_FAILED;
			}
		}
#endif
	}

finish:
	if (flock(nLockFd, LOCK_UN) < 0)
		LOGF_LOG_DEBUG("unlock failed with reason [%s]\n",
		strerror(errno));

	if (close(nLockFd) < 0)
		LOGF_LOG_DEBUG("close failed with reason [%s]\n",
		strerror(errno));

	return nRet;
}

int fapi_ssGetActiveBank(unsigned char **pcState)
{
	unsigned char *env_data = NULL;

	readenv();

	env_data = get_env("active_bank");
	if (env_data == NULL)
		return UBOOT_VARIABLE_NOT_EXIST;

	*pcState = env_data;

	return UGW_SUCCESS;
}

int fapi_ssGetUbootParam(char *name, uboot_value_t *pcparam, bool env_valid)
{
	unsigned char *env_data = NULL;
	int value, ret = 0;

	if (name == NULL) {
		printf("invalid env arg\n");
		return UBOOT_VARIABLE_NOT_EXIST;
	}

	if (env_valid == false) {
		ret = readenv();
		if (ret == GET_DEVICE_INFO_DATA_FAILURE)
			return GET_DEVICE_INFO_DATA_FAILURE;
	}

	env_data = get_env(name);
	if (env_data == NULL) {
		printf("variable %s doesn't exists in uboot.\n", name);
		return UBOOT_VARIABLE_NOT_EXIST;
	}

	if (pcparam->type == STRING) {
		pcparam->u.valuec = (char *)env_data;
	} else if (pcparam->type == INTEGER) {
		value = atoi((char *)env_data);
		pcparam->u.valuei = value;
	}

	return UGW_SUCCESS;
}

int fapi_ssSetUbootParam(char *name, uboot_value_t *pvalue)
{
	int ret = 0;
	char value[255];
	unsigned char *env_data = NULL;

	if (!name)
		return UBOOT_NAME_NULL;

	if (!pvalue)
		return UBOOT_VALUE_ERROR;

	ret = readenv();
	if(ret == GET_DEVICE_INFO_DATA_FAILURE)
		return GET_DEVICE_INFO_DATA_FAILURE;

	env_data = get_env(name);
	if (env_data == NULL) {
		printf("variable %s doesn't exists in uboot.\n", name);
		return UBOOT_VARIABLE_NOT_EXIST;
	}
	if (pvalue->type == STRING) {
		strncpy_s(value, sizeof(value),
			  pvalue->u.valuec, strlen(pvalue->u.valuec));
		ret = set_env(name, value);
		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;
		saveenv();
	} else if (pvalue->type == INTEGER) {
		snprintf(value, sizeof(value), "%d", pvalue->u.valuei);
		ret = set_env(name, (char *)value);
		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;
		saveenv();
	}
	return UGW_SUCCESS;
}

int fapi_ssSetCommitBank(unsigned char *value)
{
	int ret = 0;

	readenv();

	if (value != NULL) {
		ret = set_env("commit_bank", (char *)value);
		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;
		saveenv();
	}

	return UGW_SUCCESS;
}

int fapi_ssGetCommitBank(unsigned char **pcState)
{
	unsigned char *env_data = NULL;

	readenv();

	env_data = get_env("commit_bank");
	if (!env_data)
		return UBOOT_VARIABLE_NOT_EXIST;

	*pcState = env_data;

	return UGW_SUCCESS;
}

int fapi_ssActivateBank(unsigned char *pvalue)
{
	int ret = 0;

	readenv();

	if (!pvalue)
		return UBOOT_VALUE_ERROR;

	if (pvalue != NULL) {
		ret = set_env("img_activate", (char *)pvalue);
		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;
		saveenv();
	}

	return UGW_SUCCESS;
}

int fapi_ssSetUdt(unsigned char *pvalue, uint32_t ivalue)
{
	int ret = 0;
	char value[255];

	readenv();

	if (!pvalue)
		return UBOOT_VALUE_ERROR;

	if (pvalue != NULL) {
		ret = set_env("udt_file", (char *)pvalue);

		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;

		snprintf(value, sizeof(value), "%d", ivalue);
		ret = set_env("udt_status", (char *)value);

		if (ret != UGW_SUCCESS)
			return UBOOT_SET_OPERATION_FAIL;

		saveenv();
	}
	return UGW_SUCCESS;
}

#ifdef LINUX_UPGRADE
static int add_uboot_param(const char *uboot_var, const int value)
{
	FILE *fp = NULL;
	char cmd[MAX_PATH_LEN] = {0};

	sprintf_s(cmd, sizeof(cmd), "/usr/sbin/uboot_env --get --name %s", uboot_var);
	if (system(cmd) == 0)
		return 0;
	memset(cmd, 0, sizeof(cmd));
	sprintf_s(cmd, sizeof(cmd), "/usr/sbin/uboot_env --add --name %s --value %d", uboot_var, value);
	fp = popen(cmd, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error launching the cmd to update the uboot environment\n");
		return -ENOENT;
	}
	if (pclose(fp) < 0 ) {
		fprintf(stderr, "Error setting the environement variable\n");
		return -ENOENT;
	}
	return 0;
}

static int set_uboot_param_int(const char *var_name, const int value)
{
	FILE *fp = NULL;
	char cmd[MAX_PATH_LEN] = {0};

	sprintf_s(cmd, sizeof(cmd), "/usr/sbin/uboot_env --set --name %s --value %d", var_name, value);
	fp = popen(cmd, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error launching the cmd to update the uboot environment\n");
		return -ENOENT;
	}
	if (pclose(fp) < 0 ) {
		fprintf(stderr, "Error setting the environement variable\n");
		return -ENOENT;
	}
	return 0;
}

static int set_uboot_param_str(const char *var_name, const char* value)
{
	FILE *fp = NULL;
	char cmd[MAX_PATH_LEN] = {0};
	sprintf_s(cmd, sizeof(cmd), "/usr/sbin/uboot_env --set --name %s --value %s", var_name, value);
	fp = popen(cmd, "w");
	if (fp == NULL) {
		fprintf(stderr, "Error launching the cmd to update the uboot environment\n");
		return -ENOENT;
	}
	if (pclose(fp) < 0 ) {
		fprintf(stderr, "Error setting the environement variable\n");
		return -ENOENT;
	}
	return 0;
}

static int get_uboot_param(char *var_name, char *value)
{
	FILE *output = NULL;
	char name[MAX_PATH_LEN] = {0};
	char cmd[MAX_PATH_LEN] = {0};

	sprintf_s(cmd, sizeof(cmd), "/usr/sbin/uboot_env --get --name %s", var_name);
	output = popen(cmd, "r");
	if (output == NULL) {
		fprintf(stderr, "Error launching the cmd to get %s the uboot environment\n", var_name);
		return -ENOENT;
	}
	if (fread(name, 1, MAX_PATH_LEN, output) > 0) {
		strncpy_s(value, MAX_PATH_LEN, name, MAX_PATH_LEN);
		if (value[strnlen_s(name, MAX_PATH_LEN) - 1] == '\n')
			value[strnlen_s(name, MAX_PATH_LEN) - 1] = 0;
	} else {
		fprintf(stderr, "%s variable not found in uboot\n", var_name);
		return -ENOENT;
	}

	pclose(output);
	return 0;
}

static int img_validate_and_commit(void)
{
	int i, ret = 0, val;
	char cPath[MAX_PATH_LEN] = {0};

	if (get_uboot_param("upgrade_image", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		ret = -ENOENT;
		goto finish;
	}
	val = atoi(cPath);
	for (i = 0; i < ARRAY_SIZE(image_list); i++) {
		if (image_list[i] != val) {
			ret = -EINVAL;
			continue;
		} else {
			if ((val & BOOTLOADER) || (val & BOOTLOADERFIT)) {
				/* UBOOT */
				ret = fapi_ssImgValidateAndCommit("u-boot", 0); // earlier it was uboot
				if (ret != 0) {
					ret = -EPERM;
					goto finish;
				}
			}
			if (val & RBE) {
				/* RBE */
				memset(cPath, 0, sizeof(cPath));
				if (get_uboot_param("rbe_size", cPath) != 0) {
					fprintf(stderr, "Failed to get variable\n");
					ret = -ENOENT;
					goto finish;
				}
				ret = fapi_ssImgValidateAndCommit("rbe", atoi(cPath));
				if (ret != 0) {
					ret = -EPERM;
					goto finish;
				}
			}
			if ((val & TEP) || (val & TEPFIT)) {
				/* TEP Firmware */
				memset(cPath, 0, sizeof(cPath));
				if (get_uboot_param("tep_size", cPath) != 0) {
					fprintf(stderr, "Failed to get variable\n");
					ret = -ENOENT;
					goto finish;
				}
				ret = fapi_ssImgValidateAndCommit("tep", atoi(cPath));
				if (ret != 0) {
					ret = -EPERM;
					goto finish;
				}
			}
			if ((val & KERNEL) || (val & KERNELDTBFIT)) {
				/* kernel */
#ifdef IMG_AUTH
				ret = fapi_ssImgValidateAndCommit("kernel", 0);
				if (ret != 0) {
					ret = -EPERM;
					goto finish;
				}
#else
				ret = 0;
#endif
			}
			if ((val & ROOTFS) || (val & ROOTFSFIT)) {
				/* rootfs */
#ifdef IMG_AUTH
				memset(cPath, 0, sizeof(cPath));
				if (get_uboot_param("rootfs_size", cPath) != 0) {
					fprintf(stderr, "Failed to get variable\n");
					ret = -ENOENT;
					goto finish;
				}
				ret = fapi_ssImgValidateAndCommit("rootfs", atoi(cPath));
				if (ret != 0)
					ret = -EPERM;
#else
				ret = 0;
#endif
			}
			if (val & DTB) {
				fprintf(stderr, "DTB Image, nothing to be done\n");
				ret = 0;
			}
			break;
		}
	}
finish:
	return ret;
}


/**=====================================================================
 * @brief  API to switch activebank
 *
 * @param actbnk bank to switch
 *
 * @return
 *  0 on success
 *  error code on failure
 =======================================================================
 */
int fapi_Switch_bank(char *actbnk)
{
	int nRet = 0;
	if (!(strcmp(actbnk, "A") == 0 || strcmp(actbnk, "B") == 0)) {
		LOGF_LOG_ERROR("Invalid active_bank '%s'\n", actbnk);
		nRet = -EINVAL;
	}
	if (set_uboot_param_str("active_bank", actbnk) != 0) {
		fprintf(stderr, "Failed to set active_bank\n");
		nRet = -EPERM;
	}
	return nRet;
}

/**=====================================================================
 * @brief  API to get last upgrade status
 *
 * @param value upgrade status  
 *
 * @return
 *  0 on success
 *  error code on failure
 =======================================================================
 */
int fapi_Get_lastupg_status(char *value)
{
	char cPath[MAX_PATH_LEN] = {0};
	if (get_uboot_param("last_upg_status", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		return -ENOENT;
	}
	strncpy_s(value, MAX_PATH_LEN, cPath, MAX_PATH_LEN);
	return 0;
}

/**=====================================================================
 * @brief  API to get last upgrade time
 *
 * @param value upgrade time 
 *
 * @return
 *  0 on success
 *  error code on failure
 =======================================================================
 */
int fapi_Get_lastupg_time(char *value)
{
	char cPath[MAX_PATH_LEN] = {0};
	if (get_uboot_param("last_upg_time", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		return -ENOENT;
	}
	strncpy_s(value, MAX_PATH_LEN, cPath, MAX_PATH_LEN);
	return 0;
}

/**=====================================================================
 * @brief  API to commit image
 *
 * @param void
 *
 * @return
 *  0 on success
 *  error code on failure
 =======================================================================
 */
int fapi_Image_commit(void)
{
	int ret = 0, udt_status;
	char cPath[MAX_PATH_LEN] = {0};
	struct timespec ts;
	struct tm *tm_info;
	char date_string[MAX_PATH_LEN];

	if (access("/tmp/.upg_progress", F_OK) == 0) {
		fprintf(stderr, "upgrade in progress, do reboot before commit\n");
		return -ECANCELED;
	}

	/*get date and time info*/
	clock_gettime(CLOCK_REALTIME, &ts);
	tm_info = localtime(&ts.tv_sec);
	strftime(date_string, sizeof(date_string), "%Y%m%d%H%M%S", tm_info);
	//fprintf(stderr,"Current date and time: %s\n", date_string);
	
	if (get_uboot_param("udt_status", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		ret = -ENOENT;
		goto finish;
	}
	/* check udt_status is UDT_UPG_LINUX_NEW_IMAGE or not */
	udt_status = atoi(cPath);
	if (udt_status != UDT_NEW_IMAGE) {
		if (udt_status != UDT_IMAGE_RECOVERED) {
			fprintf(stderr, "udt_status value not Recovered or New Image, commit failed\n");
			return -ECANCELED;
		} else {
			fprintf(stdout, "A new S/W UPGRADE, in previous boot, failed and rejected." 
					"The original version was RECOVERED\n");
			if (set_uboot_param_str("last_upg_time", date_string) != 0) {
				fprintf(stderr, "Failed to set last_upg_time'\n");
				ret = -EPERM;
			}
			if (set_uboot_param_str("last_upg_status", "Failed") != 0) {
				fprintf(stderr, "Failed to set 'last_upg_status' as 'Failed'\n");
				ret = -EPERM;
			}
			if (set_uboot_param_int("rbe_size", 0) != 0) {
				fprintf(stderr, "Failed to set 'rbe_size' to 0\n");
				ret = -EPERM;
			}
			if (set_uboot_param_int("tep_size", 0) != 0) {
				fprintf(stderr, "Failed to set 'tep_size' to 0\n");
				ret = -EPERM;
			}
			if (set_uboot_param_int("rootfs_size", 0) != 0) {
				fprintf(stderr, "Failed to set 'rootfs_size' to 0\n");
				ret = -EPERM;
			}
			if (set_uboot_param_int("upgrade_image", 0) != 0) {
				fprintf(stderr, "Failed to set 'upgrade_image' to 0\n");
				ret = -EPERM;
			}
			if (set_uboot_param_str("early_boot", "valid") != 0) {
				fprintf(stderr, "Failed to set 'early_boot' as 'valid'\n");
				ret = -EPERM;
			}
			if (set_uboot_param_str("late_boot", "valid") != 0) {
				fprintf(stderr, "Failed to set 'late_boot' as 'valid'\n");
				ret = -EPERM;
			}
			if (set_uboot_param_int("udt_status", UDT_IMAGE_NO_ACTION) != 0) {
				fprintf(stderr, "Fail to set 'udt_status' to zero\n");
				ret = -EPERM;
			}
		}
	} else {
		
		fprintf(stdout, 
			"A new S/W UPGRADE, in previous boot, was detected and accepted."
			"Now Commiting the image.\n");
		if (set_uboot_param_str("last_upg_time", date_string) != 0) {
			fprintf(stderr, "Failed to set last_upg_time'\n");
			ret = -EPERM;
		}
		if (set_uboot_param_str("last_upg_status", "Success") != 0) {
			fprintf(stderr, "Failed to set 'last_upg_status' as 'Failed'\n");
			ret = -EPERM;
		}
		ret = img_validate_and_commit();
		if (ret < 0) {
			fprintf(stderr, "Image commit failed\n");
			goto finish;
		}
		memset(cPath, 0, sizeof(cPath));
		if (get_uboot_param("early_boot", cPath) != 0) {
			fprintf(stderr, "Failed to get variable\n");
			ret = -ENOENT;
		}
		if (strncmp(cPath, "upgrade", strlen("upgrade")) == 0 ) {
			if (set_uboot_param_str("early_boot", "valid") != 0) {
				fprintf(stderr, "Failed to set 'early_boot' to valid\n");
				ret = -EPERM;
				goto finish;
			}
			memset(cPath, 0, sizeof(cPath));
			if (get_uboot_param("rbe_size", cPath) != 0) {
				fprintf(stderr, "Failed to get variable\n");
				ret = -ENOENT;
			}
			if (atoi(cPath) != 0)
				if (set_uboot_param_int("rbe_size", 0) != 0) {
					fprintf(stderr, "Failed to set 'rbe_size' to 0\n");
					ret = -EPERM;
					goto finish;
				}
			memset(cPath, 0, sizeof(cPath));
			if (get_uboot_param("tep_size", cPath) != 0) {
				fprintf(stderr, "Failed to get variable\n");
				ret = -ENOENT;
			}
			if (atoi(cPath) != 0)
				if (set_uboot_param_int("tep_size", 0) != 0) {
					fprintf(stderr, "Failed to set 'tep_size' to 0\n");
					ret = -EPERM;
					goto finish;
				}
		}
		memset(cPath, 0, sizeof(cPath));
		if (get_uboot_param("late_boot", cPath) != 0) {
			fprintf(stderr, "Failed to get variable\n");
			ret = -ENOENT;
		}
		if (strncmp(cPath, "upgrade", strlen("upgrade")) == 0 ) {
			if (set_uboot_param_str("late_boot", "valid") != 0) {
				fprintf(stderr, "Setting the late_boot value Failed as valid\n");
				ret = -EPERM;
				goto finish;
			}
			memset(cPath, 0, sizeof(cPath));
			if (get_uboot_param("rootfs_size", cPath) != 0) {
				fprintf(stderr, "Failed to get variable\n");
				ret = -ENOENT;
			}
			if (atoi(cPath) != 0)
				if (set_uboot_param_int("rootfs_size", 0) != 0) {
					fprintf(stderr, "Failed to set 'rootfs_size' to 0\n");
					ret = -EPERM;
					goto finish;
				}
		}
		memset(cPath, 0, sizeof(cPath));
		if (get_uboot_param("upgrade_image", cPath) != 0) {
			fprintf(stderr, "Failed to get variable\n");
			ret = -ENOENT;
		}
		if (atoi(cPath) != 0)
			if (set_uboot_param_int("upgrade_image", 0) != 0) {
				fprintf(stderr, "Failed to set 'upgrade_image' to 0\n");
				ret = -EPERM;
				goto finish;
			}
		if (set_uboot_param_int("udt_status", UDT_IMAGE_NO_ACTION) != 0) {
			fprintf(stderr, "Fail to set 'udt_status' to zero\n");
			ret = -EPERM;
			goto finish;
		}
	}
finish:
	return ret;
}

static int image_hdr_validation(image_header_t *pxImgHeader)
{
	/* if mkimage header is not available, exit */
	if (pxImgHeader) {
		switch (ntohl(pxImgHeader->img_hdr_magic)) {
			case IMG_HDR_MAGIC:
				if (!is_image_hcrc_valid(pxImgHeader)) {
					fprintf(stderr, "Bad Header Checksum\n");
					return -EINVAL;
				}
				fprintf(stdout, "Successful validation of image header and checksum\n");
				break;
			case FLATDT_MAGIC:
				/* DTB crc is not available, so not added checking for it */
				break;
			default:
				fprintf(stderr, "no mkimage header\n");
				return -EINVAL;
		}
	}

	return 0;
}
int upgrade_nested_fit(const void *fit, img_param_t image_auth, int *early_boot)
{
	int noffset;
	int depth = 0, len = 0;
	const void *data;
	void *aligned_node_buf = NULL;
	const char* node_name;
	
	noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (noffset < 0) {
		fprintf(stderr, "FIT is missing image nodes\n");
		return -EINVAL;
	}
	
	while ((noffset = fdt_next_node(fit, noffset, &depth)) >= 0) {
		if (depth < 1)
			break;
		if (depth == 1) {
			fprintf(stdout,"\nnoffset %d depth %d name %s\n", noffset, depth,
                      		fdt_get_name(fit, noffset, NULL));
			data = fdt_getprop(fit, noffset, FIT_DATA_PROP, &len);
			if (!data || len <= 0)
				continue;
			
			aligned_node_buf = malloc(len);
			if(aligned_node_buf == NULL) {
				return -EINVAL;
			}
			memcpy(aligned_node_buf, data, len);
			
			node_name = fdt_get_name(fit, noffset, NULL);	
			if((strcmp(node_name, "uboot") == 0) || (strcmp(node_name, "tep") == 0)
				|| (strcmp(node_name, "rbe") == 0)) {
				*early_boot = 1;
				strncpy_s(image_auth.img_name, sizeof(image_auth.img_name), node_name, strlen(node_name));
			} else if(strcmp(node_name, "kernel-dtb") == 0) {
				strncpy_s(image_auth.img_name, sizeof(image_auth.img_name), "kernel", strlen("kernel"));
			} else if(strcmp(node_name, "filesystem") == 0) {
				strncpy_s(image_auth.img_name, sizeof(image_auth.img_name), "rootfs", strlen("rootfs"));
			}
			if (!fdt_check_header(aligned_node_buf)) { 
				image_auth.src_img_addr = (unsigned char *)aligned_node_buf;
			} else {
				if (strcmp(node_name, "rbe") == 0) {
 					/*RBE image came here, may be part of total image.Pass just the data as RBE is not fit image*/
					image_auth.src_img_addr = (unsigned char *)aligned_node_buf;
				} else {
					image_auth.src_img_addr = (unsigned char *)fit;
				}
			}
			fprintf(stdout, "fapi_ssImgUpgrade called for %s\n", image_auth.img_name);
			if (fapi_ssImgUpgrade(image_auth) < 0) {
				fprintf(stderr, "%s Image upgrade passed\n", image_auth.img_name);
				if (aligned_node_buf != NULL) {
					free(aligned_node_buf);
					aligned_node_buf = NULL;
				}
				return -EPERM;
			} else 
				fprintf(stderr, "%s Image upgrade passed\n", image_auth.img_name);
				
		}
	}
	if (aligned_node_buf != NULL) {
		free(aligned_node_buf);
		aligned_node_buf = NULL;
	}
	return fdt_totalsize(fit);
}
int validate_nested_fit(const void *fit, img_param_t image_auth, int *currentimage) 
{
	int noffset = -1;
	int depth = 0, len;
	const void *data;
	void *aligned_node_buf = NULL;
	const char* node_name;

	noffset = fdt_path_offset(fit, FIT_IMAGES_PATH);
	if (noffset < 0) {
		fprintf(stderr, "FIT is missing image nodes\n");
		return -EINVAL;
	}
	
	while ((noffset = fdt_next_node(fit, noffset, &depth)) >= 0) {
                LOGF_LOG_DEBUG("noffset %d depth %d name %s\n", noffset, depth,
                      fdt_get_name(fit, noffset, NULL));
		if (depth < 1)
			break;
		if (depth == 1) {
                	fprintf(stdout,"\nnoffset %d depth %d name %s\n", noffset, depth,
                      		fdt_get_name(fit, noffset, NULL));
			data = fdt_getprop(fit, noffset, FIT_DATA_PROP, &len);
			if (!data || len <= 0)
				continue;
			
			aligned_node_buf = malloc(len);
			if(aligned_node_buf == NULL) {
				return -EINVAL;
			}
			memcpy(aligned_node_buf, data, len);
			
			node_name = fdt_get_name(fit, noffset, NULL);	
			if(node_name && strcmp(node_name, "uboot") == 0) {
				*currentimage += BOOTLOADERFIT;
			} else if(node_name && strcmp(node_name, "tep") == 0) {
				*currentimage += TEPFIT;
			} else if(node_name && strcmp(node_name, "kernel-dtb") == 0) {
				*currentimage += KERNELDTBFIT;
			} else if(node_name && strcmp(node_name, "filesystem") == 0) {
				*currentimage += ROOTFSFIT;
			} else if(node_name && strcmp(node_name, "rbe") == 0) {
				*currentimage += RBE;
			} else {
				fprintf(stderr, "upgrade is not supported for %s, continuing with next image\n", image_auth.img_name);
				continue;
			}
			strncpy_s(image_auth.img_name, sizeof(image_auth.img_name), node_name, (strlen("node_name")+1));
			if (!fdt_check_header(aligned_node_buf)) {
				image_auth.src_img_addr = (unsigned char *)aligned_node_buf;
				fprintf(stdout, "Image authentication called for %s\n", image_auth.img_name);
				if (fapi_ssImgAuth(image_auth) < 0){
					fprintf(stderr, "%s Validation failed\n", image_auth.img_name);
					if (aligned_node_buf != NULL)
						free(aligned_node_buf);
					return -EPERM;
				} else 
					fprintf(stdout, "%s Validation passed\n", image_auth.img_name);
			} else {
				if (strcmp(node_name, "rbe") == 0) {
					/*RBE image came here, may be part of total image*/
					image_auth.src_img_addr = (unsigned char *)aligned_node_buf; 
				}
				else { 
					image_auth.src_img_addr = (unsigned char *)fit;
				}
				fprintf(stdout, "Image authentication called for %s\n", image_auth.img_name);
				if (fapi_ssImgAuth(image_auth) < 0){
					fprintf(stderr, "%s Validation failed\n", image_auth.img_name);
					if (aligned_node_buf != NULL)
						free(aligned_node_buf);
					return -EPERM;
				} else 
					fprintf(stderr, "\n%s Validation passed\n", image_auth.img_name);
			}
		}
	}
	if (aligned_node_buf != NULL)
		free(aligned_node_buf);
	return fdt_totalsize(fit);
}

static int validate_image(const img_param_t img)
{
	uint32_t cur_par_size=0, pad, file_read_size =0, total_file_read_size = 0;
	unsigned char *header = NULL;
	image_header_t x_img_header, *img_header = NULL;
	char name[MAX_PATH_LEN] = {0};
	int ret = 0, i, fullimage = 0, currentimage = 0;
	img_param_t img_param;

	header = img.src_img_addr;
	do {
		x_img_header = *((image_header_t *)header);

		if(x_img_header.img_hdr_type == IMG_HDR_VAR_MULTI) {
			img_header = &x_img_header;
			if (image_hdr_validation(img_header) < 0) {
				ret = -EINVAL;
				goto finish;
			}
			fullimage = 1;
			cur_par_size = sizeof(image_header_t) + 8;
			total_file_read_size += cur_par_size;
			header = img.src_img_addr + total_file_read_size;
			continue;
		}

		cur_par_size = sizeof(image_header_t) + ntohl(x_img_header.img_hdr_size);
		pad = (16 - (cur_par_size % 16)) % 16;
		header = img.src_img_addr + total_file_read_size;
		file_read_size = cur_par_size + pad;

		img_header = &x_img_header;
		if (image_hdr_validation(img_header) < 0) {
			ret = -EINVAL;
			goto finish;
		}
		if (ntohl(*(uint32_t *)header) == FLATDT_MAGIC) {
			if (fullimage != 1) {
				ret = validate_nested_fit((void *)header, img_param, &currentimage);
				if(ret > 0) {
					file_read_size = ret;
					header += sizeof(image_header_t);
					ret = 0;
					fprintf(stdout, "validate_nested_fit passed file_read_size %u\n", file_read_size);
					goto dtb_finish;
				
				} else if(ret < 0) { 
					fprintf(stderr, " validate_nested_fit returned err , %s Image Validation failed\n", img_param.img_name);
					ret = -EPERM;
					goto finish;
				}
			} else {
				currentimage |= DTB;
				memcpy(&img_param, &img, sizeof(img));
				strncpy_s(img_param.img_name, sizeof(img_param.img_name), "dtb", strlen("dtb"));
				img_param.src_img_addr = header;
				ret = fapi_ssImgAuth(img_param);
				if (ret < 0) {
					fprintf(stderr, "%s Image Validation failed\n", img_param.img_name);
					ret = -EPERM;
					goto finish;
				}
				file_read_size = ret;
				header += sizeof(image_header_t);
				ret = 0;
				goto dtb_finish;
			}
		}

		switch(x_img_header.img_hdr_type) {
			case IMG_HDR_VAR_FILESYSTEM:
				if (fullimage != 1) {
					fprintf(stderr, "Only Rootfs image upgrade not supported!\n");
					ret = -EINVAL;
					goto finish;
				}
				currentimage |= ROOTFS;
				sprintf_s(name, sizeof(name),"rootfs");
				break;
			case IMG_HDR_VAR_KERNEL:
				if (fullimage != 1) {
					fprintf(stderr, "Only kernel image upgrade not supported!\n");
					ret = -EINVAL;
					goto finish;
				}
				currentimage |= KERNEL;
				sprintf_s(name, sizeof(name),"kernel");
				break;
			case IMG_HDR_VAR_FIRMWARE:
				if (strncmp((char *)x_img_header.img_hdr_name, "RBE", sizeof(x_img_header.img_hdr_name)) == 0) {
					sprintf_s(name, sizeof(name), "rbe");
					currentimage |= RBE;
				} else if (strncmp((char *)x_img_header.img_hdr_name, "TEP firmware", sizeof(x_img_header.img_hdr_name)) == 0) {
					sprintf_s(name, sizeof(name),"firmware");
					currentimage |= TEP;
				} else {
					fprintf(stderr, "Unknown image type, not a RBE or TEP!!\n");
					ret = -EINVAL;
					goto finish;
				}
				break;
			case IMG_HDR_VAR_UBOOT:
				sprintf_s(name, sizeof(name), "uboot");
				currentimage |= BOOTLOADER;
				break;
			default:
				fprintf(stderr, "Unknown image type!!\n");
				ret = -EINVAL;
				goto finish;
		}
		memcpy(&img_param, &img, sizeof(img));
		strncpy_s(img_param.img_name, MAX_PATH_LEN, name, MAX_PATH_LEN);

		img_param.src_img_addr = header;
		if ((x_img_header.img_hdr_type != IMG_HDR_VAR_KERNEL) &&
			(x_img_header.img_hdr_type != IMG_HDR_VAR_UBOOT))
			img_param.src_img_len = file_read_size - pad - sizeof(image_header_t);
		else
			img_param.src_img_len = file_read_size - pad;

		ret = fapi_ssImgAuth(img_param);
		if (ret != 0) {
			fprintf(stderr, "%s Image validation failed\n", img_param.img_name);
			ret = -EPERM;
			goto finish;
		}
dtb_finish:
		total_file_read_size += file_read_size;

		if ((x_img_header.img_hdr_type != IMG_HDR_VAR_KERNEL) &&
			(x_img_header.img_hdr_type != IMG_HDR_VAR_UBOOT))
			header += cur_par_size;
		else
			header += file_read_size;
	} while (img.src_img_len > total_file_read_size);

	for (i = 0; i < ARRAY_SIZE(image_list); i++) {
		if (image_list[i] != currentimage) {
			ret = -EINVAL;
			continue;
		}
		
		fprintf(stderr, "provided image list %d is supported for upgrade\n",currentimage);
		ret = set_uboot_param_int("upgrade_image", currentimage);
		if (ret < 0) {
			fprintf(stderr, "Setting the upgrade_image value Failed\n");
			ret = -EINVAL;
			goto finish;
		}
		break;
	}

finish:
	return ret;
}

static int upgrade_image(const img_param_t img)
{
	uint32_t cur_par_size=0, pad, file_read_size =0, total_file_read_size = 0;
	unsigned char *header = NULL;
	image_header_t x_img_header;
	char name[MAX_PATH_LEN] = {0}, early_boot[MAX_PATH_LEN] = {0}, late_boot[MAX_PATH_LEN] = {0};
	char cPath[MAX_PATH_LEN] = {0};
	int ret = 0, fullimage = 0;
	img_param_t img_param;
	int earlyboot = 0;
	header = img.src_img_addr;
	do {
		x_img_header = *((image_header_t *)header);

		if(x_img_header.img_hdr_type == IMG_HDR_VAR_MULTI) {
			fullimage = 1;
			cur_par_size = sizeof(image_header_t) + 8;
			total_file_read_size += cur_par_size;
			header =  img.src_img_addr + total_file_read_size;
			continue;
		}

		cur_par_size = sizeof(image_header_t) + ntohl(x_img_header.img_hdr_size);
		pad = (16 - (cur_par_size % 16)) % 16;
		header =  img.src_img_addr + total_file_read_size;
		file_read_size = cur_par_size + pad;

		if (ntohl(*(uint32_t *)header) == FLATDT_MAGIC) {
			memcpy(&img_param, &img, sizeof(img));
			img_param.src_img_addr = header;
			if (fullimage != 1) {
				ret = upgrade_nested_fit((void *)header, img_param, &earlyboot);
				if (ret > 0) {
					if (earlyboot == 1)
						sprintf_s(early_boot, sizeof(name), "early_boot");
					else
						sprintf_s(late_boot, sizeof(name), "late_boot");

					file_read_size = ret;
					header += sizeof(image_header_t);
					ret = 0;
					goto dtb_finish;
				} else if (ret < 0) {
					fprintf(stderr, "\nupgrade_nested_fit returned err , %s Image upgrade failed\n", img_param.img_name);
					ret = -EPERM;
					goto finish;
				}
			} else {
				strncpy_s(img_param.img_name, sizeof(img_param.img_name), "dtb", strlen("dtb"));
				ret = fapi_ssImgUpgrade(img_param);
				if (ret < 0) {
					fprintf(stderr, "%s Image upgrade failed\n", img_param.img_name);
					ret = -EINVAL;
					goto finish;
				}
				sprintf_s(late_boot, sizeof(name), "late_boot");
				file_read_size = ret;
				header += sizeof(image_header_t);
				ret = 0;
				goto dtb_finish;
			}
		}

		switch(x_img_header.img_hdr_type) {
			case IMG_HDR_VAR_FILESYSTEM:
				if (fullimage != 1) {
					fprintf(stderr, "Only Rootfs image upgrade not supported!\n");
					ret = -EINVAL;
					goto finish;
				}
				sprintf_s(name, sizeof(name),"rootfs");
				sprintf_s(late_boot, sizeof(name), "late_boot");
				break;
			case IMG_HDR_VAR_KERNEL:
				if (fullimage != 1) {
					fprintf(stderr, "Only kernel image upgrade not supported!\n");
					ret = -EINVAL;
					goto finish;
				}
				sprintf_s(name, sizeof(name),"kernel");
				sprintf_s(late_boot, sizeof(name), "late_boot");
				break;
			case IMG_HDR_VAR_FIRMWARE:
				if (strncmp((char *)x_img_header.img_hdr_name, "RBE", sizeof(x_img_header.img_hdr_name)) == 0)
					sprintf_s(name, sizeof(name), "rbe");
				else if (strncmp((char *)x_img_header.img_hdr_name, "TEP firmware", sizeof(x_img_header.img_hdr_name)) == 0)
					sprintf_s(name, sizeof(name),"firmware");
				else {
					fprintf(stderr, "Unknown image type, not a RBE or TEP!!\n");
					ret = -EINVAL;
					goto finish;
				}
				sprintf_s(early_boot, sizeof(name), "early_boot");
				break;
			case IMG_HDR_VAR_UBOOT:
				sprintf_s(name, sizeof(name), "uboot");
				sprintf_s(early_boot, sizeof(name), "early_boot");
				break;
			default:
				fprintf(stderr, "Unknown image type!!\n");
				ret = -EINVAL;
				goto finish;
		}
		memcpy(&img_param, &img, sizeof(img));
		strncpy_s(img_param.img_name, MAX_PATH_LEN, name, MAX_PATH_LEN);

		if (ntohl(x_img_header.img_hdr_magic) == IMG_HDR_MAGIC) {
			fprintf(stdout, "Image contains header with name [%s]\n",x_img_header.img_hdr_name);
			if ((x_img_header.img_hdr_type != IMG_HDR_VAR_KERNEL) &&
				(x_img_header.img_hdr_type != IMG_HDR_VAR_UBOOT)) {
				fprintf(stdout, "This is not kernel or uboot image and so removing header\n");
				header += sizeof(image_header_t);
				cur_par_size -= sizeof(image_header_t);
			}
		}

		img_param.src_img_addr = header;
		if ((x_img_header.img_hdr_type != IMG_HDR_VAR_KERNEL) &&
			(x_img_header.img_hdr_type != IMG_HDR_VAR_UBOOT))
			img_param.src_img_len = file_read_size - pad - sizeof(image_header_t);
		else
			img_param.src_img_len = file_read_size - pad;

		ret = fapi_ssImgUpgrade(img_param);
		if (ret == 0) {
			if (x_img_header.img_hdr_type == IMG_HDR_VAR_FILESYSTEM) {
				if (set_uboot_param_int("filesystem_size", img_param.src_img_len) != 0) {
					fprintf(stderr, "Setting the filesystem_size value Failed\n");
					ret = -EINVAL;
					goto finish;
				}
				if (set_uboot_param_int("rootfs_size", img_param.src_img_len) != 0) {
					fprintf(stderr, "Setting the rootfs_size value Failed\n");
					ret = -EINVAL;
					goto finish;
				}
			} else if (strncmp((char *)x_img_header.img_hdr_name, "RBE", sizeof(x_img_header.img_hdr_name)) == 0) {
				if (set_uboot_param_int("rbe_size", img_param.src_img_len) != 0) {
					fprintf(stderr, "Setting the rbe_size value Failed\n");
					ret = -EINVAL;
					goto finish;
				}
			} else if (strncmp((char *)x_img_header.img_hdr_name, "TEP firmware", sizeof(x_img_header.img_hdr_name)) == 0) {
				if (set_uboot_param_int("tep_size", img_param.src_img_len) != 0) {
					fprintf(stderr, "Setting the tep_size value Failed\n");
					ret = -EINVAL;
					goto finish;
				}
			}
		} else {
			fprintf(stderr, "%s Image Upgrade failed\n", img_param.img_name);
			ret = -EINVAL;
			goto finish;
		}
dtb_finish:
		total_file_read_size += file_read_size;

		if ((x_img_header.img_hdr_type != IMG_HDR_VAR_KERNEL) &&
			(x_img_header.img_hdr_type != IMG_HDR_VAR_UBOOT))
			header += cur_par_size;
		else
			header += file_read_size;
	} while (img.src_img_len > total_file_read_size);

	if (ret == 0) {
		if (strncmp(early_boot, "early_boot", strlen("early_boot")) == 0) {
			if (set_uboot_param_str("early_boot", "upgrade") != 0) {
				fprintf(stderr, "Setting the early boot status Failed\n");
				ret = -EINVAL;
				goto finish;
			}
		}
		if (strncmp(late_boot, "late_boot", strlen("late_boot")) == 0) {
			memset(cPath, 0, sizeof(cPath));
			if (get_uboot_param("active_bank", cPath) != 0) {
				fprintf(stderr, "Failed to get variable\n");
				ret = -ENOENT;
				goto finish;
			}
			if (cPath[0] == 'A')
				ret = set_uboot_param_str("active_bank", "B");
			else if (cPath[0] == 'B')
				ret = set_uboot_param_str("active_bank", "A");
			else
				ret = -EINVAL;
			if (ret != 0) {
				fprintf(stderr, "Toggle active bank Failed\n");
				ret = -EINVAL;
				goto finish;
			}
			if (set_uboot_param_str("late_boot", "upgrade") != 0) {
				fprintf(stderr, "Setting the late boot status Failed\n");
				ret = -EINVAL;
				goto finish;
			}
		}
	}
finish:
	return ret;
}

/**=====================================================================
 * @brief  image upgrade from linux
 *
 * @param path
 * image path to be updated
 *
 * @return
 *  0 on success
 *  error code on failure
 =======================================================================
 */
int fapi_Image_upgrade(const char *path)
{
	int ret = 0, val = 0, file_fd = 0, flag = 0;
	struct stat filestat = {0};
	img_param_t img, img_param;
	char cPath[MAX_PATH_LEN] = {0};
	
	if (get_uboot_param("udt_status", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		ret = -ENOENT;
		goto finish;
	}
	if (atoi(cPath) != UDT_IMAGE_NO_ACTION) {
		fprintf(stderr, "Previous Upgrade not completed yet as udt_status is %d!!!\n", atoi(cPath));
		ret = -ECANCELED;
		goto finish;
	}
	file_fd = open(path, O_RDONLY);
	if (file_fd < 0) {
		fprintf(stderr, "The file %s could not be opened\n", path);
		ret = -ENOENT;
		goto finish;
	}

	if (fstat(file_fd, &filestat)) {
		fprintf(stderr, "fstat error: [%s]\n",strerror(errno));
		close(file_fd);
		ret = -ENOENT;
		goto finish;
	}

	img.src_img_fd=file_fd;
	img.src_img_len=filestat.st_size;
	if (!img.src_img_len) {
		fprintf(stderr, "Empty File...\n");
		ret = -ENOENT;
		goto finish;
	} else {
		img.src_img_addr = mmap(0, img.src_img_len, PROT_READ, MAP_SHARED, img.src_img_fd, 0);
		if(img.src_img_addr == MAP_FAILED) {
			fprintf(stderr, "MMAP failed... %s\n",strerror(errno));
			ret = -ENOENT;
			goto finish;
		}
		flag = 1;
	}
	ret = add_uboot_param("upgrade_image", 0);
	if (ret < 0) {
		fprintf(stderr, "upgrade_image value addition Failed\n");
		goto finish;
	}

	memcpy(&img_param, &img, sizeof(img));
	ret = validate_image(img_param);
	if (ret < 0) {
		fprintf(stderr, "Image validation failed\n");
		goto finish;
	}
	fprintf(stdout, "Image validation passed \n");
	if (set_uboot_param_int("udt_status", UDT_NEW_IMAGE) != 0) {
		fprintf(stderr, "Setting the udt status Failed\n");
		ret = -EPERM;
		goto finish;
	}
	memset(cPath, 0, sizeof(cPath));
	if (get_uboot_param("upgrade_image", cPath) != 0) {
		fprintf(stderr, "Failed to get variable\n");
		ret = -ENOENT;
		goto finish;
	}
	val = atoi(cPath);

	if (((val & BOOTLOADER) == BOOTLOADER) ||
		((val & RBE) == RBE) || ((val & TEP) == TEP)) {
		if (set_uboot_param_str("early_boot", "invalid") != 0) {
			fprintf(stderr, "Setting the early boot status Failed\n");
			ret = -EPERM;
			goto finish;
		}
		if (val & TEP) {
			ret = add_uboot_param("tep_size", 0);
			if (ret < 0) {
				fprintf(stderr, "tep_size value addition Failed\n");
				goto finish;
			}
		}
		if (val & RBE) {
			ret = add_uboot_param("rbe_size", 0);
			if (ret < 0) {
				fprintf(stderr, "rbe_size value addition Failed\n");
				goto finish;
			}
		}
	}
	if (((val & KERNEL) == KERNEL) || ((val & ROOTFS) == ROOTFS) || ((val & DTB) == DTB)) {
		if (set_uboot_param_str("late_boot", "invalid") != 0) {
			fprintf(stderr, "Setting the late boot status Failed\n");
			ret = -EPERM;
			goto finish;
		}
		ret = add_uboot_param("rootfs_size", 0);
		if (ret < 0) {
			fprintf(stderr, "rootfs_size value addition Failed\n");
			goto finish;
		}
	}
	ret = upgrade_image(img);
	if (ret == 0)
		system("touch /tmp/.upg_progress");

finish:
	if ((img.src_img_addr != NULL) && (flag == 1)) {
		if(munmap(img.src_img_addr,  img.src_img_len) != 0)
			fprintf(stderr, "unmaping failied\n");
	}
	if(file_fd >= 0)
		close(file_fd);
	return ret;
}
#endif
