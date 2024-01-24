/**
 * @brief eSecure Library: PSA Protected Storage(PS) API Implementation
 * @copyright Copyright (c) 2022 Silex Insight. All Rights reserved
 * @file
 */

#include "psa/protected_storage.h"
#include "psa_esec_platform.h"

psa_status_t psa_ps_set(psa_storage_uid_t uid, size_t data_length, const void* p_data, psa_storage_create_flags_t create_flags)
{
    /* UID cannot be 0 */
    if ((uid & 0xFFFFFFFF) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (p_data == NULL && data_length != 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    struct psa_storage_info_t psInfo;
    /* Check whether UID exist */
    psa_status_t status = psa_ps_get_info(uid, &psInfo);

    if (status == PSA_SUCCESS) {
        /* Do not allow update on the data if created with WRITE_ONCE flag */
        if (psInfo.flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
            return PSA_ERROR_NOT_PERMITTED;
        }

        /* Delete the existing */
        psa_ps_remove(uid);
    }

    /* Create a new record */
    struct psa_storage_info_t storageInfo;
    storageInfo.flags = create_flags;
    storageInfo.size = data_length;
    storageInfo.capacity = data_length;

    /* Store to platform specific storage */
    return psa_plat_ps_set(uid, &storageInfo, p_data);
}

psa_status_t psa_ps_get(psa_storage_uid_t uid, size_t data_offset, size_t data_size, void* p_data, size_t* p_data_length)
{
    struct psa_storage_info_t info;

    /* UID cannot be 0 */
    if ((uid & 0xFFFFFFFF) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    *p_data_length = 0;

    /* Get the image details */
    psa_status_t retVal = psa_plat_ps_get_info(uid, &info);
    if (retVal != PSA_SUCCESS) {
        return retVal;
    }

    /* Invalid offset which overflows */
    if (data_offset > info.size) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Return only remaining */
    if (data_offset + data_size > info.size) {
        data_size = info.size - data_offset;
    }

    /* Read from the platfor specific storage */
    return psa_plat_ps_get(uid, data_offset, data_size, p_data, p_data_length);
}

psa_status_t psa_ps_get_info(psa_storage_uid_t uid, struct psa_storage_info_t* p_info)
{
    /* UID cannot be 0 */
    if ((uid & 0xFFFFFFFF) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    return psa_plat_ps_get_info(uid, p_info);
}

psa_status_t psa_ps_remove(psa_storage_uid_t uid)
{
    bool invalidUID = (uid & 0xFFFFFFFF) == 0;
    struct psa_storage_info_t info;
    
    /* UID cannot be 0 */
    if (invalidUID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Get storage details */
    psa_status_t status = psa_plat_ps_get_info(uid, &info);
    if (status != PSA_SUCCESS) {
        /* Does not exist, just return */
        return status;
    }

    /* Do not allow removing the data */
    if (info.flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
        return PSA_ERROR_NOT_PERMITTED;
    }

    return psa_plat_ps_remove(uid);
}

psa_status_t psa_ps_create(psa_storage_uid_t uid, size_t capacity, psa_storage_create_flags_t create_flags)
{
    /* UID cannot be 0 */
    if ((uid & 0xFFFFFFFF) == 0) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    struct psa_storage_info_t psInfo;
    /* Check whether UID exist */
    psa_status_t status = psa_ps_get_info(uid, &psInfo);

    if (status == PSA_SUCCESS) {
        return PSA_ERROR_ALREADY_EXISTS;
    }

    if (create_flags & PSA_STORAGE_FLAG_WRITE_ONCE) {
        return PSA_ERROR_NOT_SUPPORTED;
    }

    /* Create a new record */
    struct psa_storage_info_t storageInfo;
    storageInfo.flags = create_flags;
    storageInfo.size = 0;
    storageInfo.capacity = capacity;

    /* Store to platform specific storage */
    return psa_plat_ps_set(uid, &storageInfo, NULL);
}

psa_status_t psa_ps_set_extended(psa_storage_uid_t uid, size_t data_offset, size_t data_length, const void* p_data)
{
    bool invalidUID = (uid & 0xFFFFFFFF) == 0;

    /* UID cannot be 0 */
    if (invalidUID) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (p_data == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    struct psa_storage_info_t psInfo;
    /* Check whether UID exists */
    psa_status_t status = psa_ps_get_info(uid, &psInfo);
    if (status != PSA_SUCCESS) {
        return PSA_ERROR_DOES_NOT_EXIST;
    }

    if (data_offset > psInfo.capacity || (data_length != 0 && data_offset + data_length > psInfo.capacity)) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    /* Do not allow gap between writes */
    if (data_length > 0 && psInfo.size > 0 && psInfo.size + 1 < data_offset) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }

    if (data_length > 0) {
        status = psa_plat_ps_set_extended(uid, data_offset, data_length, p_data);
        if (status != PSA_SUCCESS) {
            return status;
        }
    }

    return PSA_SUCCESS;
}

uint32_t psa_ps_get_support(void)
{
    return PSA_STORAGE_SUPPORT_SET_EXTENDED;
}
