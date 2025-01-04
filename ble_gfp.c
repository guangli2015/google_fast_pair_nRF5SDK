/**
 * Copyright (c) 2012 - 2021, Nordic Semiconductor ASA
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form, except as embedded into a Nordic
 *    Semiconductor ASA integrated circuit in a product or a software update for
 *    such product, must reproduce the above copyright notice, this list of
 *    conditions and the following disclaimer in the documentation and/or other
 *    materials provided with the distribution.
 *
 * 3. Neither the name of Nordic Semiconductor ASA nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * 4. This software, with or without modification, must only be used with a
 *    Nordic Semiconductor ASA integrated circuit.
 *
 * 5. Any software provided in binary form under this license must not be reverse
 *    engineered, decompiled, modified and/or disassembled.
 *
 * THIS SOFTWARE IS PROVIDED BY NORDIC SEMICONDUCTOR ASA "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY, NONINFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL NORDIC SEMICONDUCTOR ASA OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include "sdk_common.h"

#include "ble.h"
#include "ble_gfp.h"
#include "ble_srv_common.h"

#define NRF_LOG_MODULE_NAME ble_gfp
#if BLE_GFP_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       BLE_GFP_CONFIG_LOG_LEVEL
#define NRF_LOG_INFO_COLOR  BLE_GFP_CONFIG_INFO_COLOR
#define NRF_LOG_DEBUG_COLOR BLE_GFP_CONFIG_DEBUG_COLOR
#else // BLE_GFP_CONFIG_LOG_ENABLED
#define NRF_LOG_LEVEL       4
#endif // BLE_GFP_CONFIG_LOG_ENABLED
#include "nrf_log.h"
NRF_LOG_MODULE_REGISTER();


#define BLE_UUID_GFP_MODEL_ID_CHARACTERISTIC 0x1233             
#define BLE_UUID_GFP_KEY_BASED_PAIRING_CHARACTERISTIC 0x1234
#define BLE_UUID_GFP_PASSKEY_CHARACTERISTIC 0x1235 
#define BLE_UUID_GFP_ACCOUNT_KEY_CHARACTERISTIC 0x1236 
#define BLE_UUID_GFP_ADDI_DATA_CHARACTERISTIC 0x1237                 

#define BLE_GFP_MAX_RX_CHAR_LEN        BLE_GFP_MAX_DATA_LEN /**< Maximum length of the RX Characteristic (in bytes). */
#define BLE_GFP_MAX_TX_CHAR_LEN        BLE_GFP_MAX_DATA_LEN /**< Maximum length of the TX Characteristic (in bytes). */

#define GFP_CHARACTERISTIC_BASE_UUID                  {{0xEA, 0x0B, 0x10, 0x32, 0xDE, 0x01, 0xB0, 0x8E, 0x14, 0x48, 0x66, 0x83, 0x00, 0x00, 0x2C, 0xFE}} /**< Used vendor specific UUID. */

#define GFP_SERVICE_UUID  0xFE2C
#if 1
/**@brief Function for handling the @ref BLE_GAP_EVT_CONNECTED event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_connect(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                 err_code;
    ble_gfp_evt_t              evt;
    ble_gatts_value_t          gatts_val;
    uint8_t                    cccd_value[2];
    ble_gfp_client_context_t * p_client = NULL;

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
                                 p_ble_evt->evt.gap_evt.conn_handle,
                                 (void *) &p_client);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
                      p_ble_evt->evt.gap_evt.conn_handle);
    }
 NRF_LOG_INFO("on_connect################################\n");

    /* Check the hosts CCCD value to inform of readiness to send data using the RX characteristic */
    memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->keybase_pair_handles.cccd_handle,
                                      &gatts_val);

    if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get keybase_pair_handles################################%d\n",err_code);
    }

        memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->addi_data_handles.cccd_handle,
                                      &gatts_val);

    if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get addi_data_handles################################%d\n",err_code);
    }

            memset(&gatts_val, 0, sizeof(ble_gatts_value_t));
    gatts_val.p_value = cccd_value;
    gatts_val.len     = sizeof(cccd_value);
    gatts_val.offset  = 0;

    err_code = sd_ble_gatts_value_get(p_ble_evt->evt.gap_evt.conn_handle,
                                      p_gfp->passkey_handles.cccd_handle,
                                      &gatts_val);

    //if ((err_code == NRF_SUCCESS))
    {
       NRF_LOG_INFO("get passkey_handles################################%d\n",err_code);
    }



}
#endif

/**@brief Function for handling the @ref BLE_GATTS_EVT_WRITE event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_write(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                    err_code;
    ble_gfp_evt_t                 evt;
    ble_gfp_client_context_t    * p_client;
    ble_gatts_evt_write_t const * p_evt_write = &p_ble_evt->evt.gatts_evt.params.write;

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
                                 p_ble_evt->evt.gatts_evt.conn_handle,
                                 (void *) &p_client);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
                      p_ble_evt->evt.gatts_evt.conn_handle);
    }

    memset(&evt, 0, sizeof(ble_gfp_evt_t));
    evt.p_gfp       = p_gfp;
    evt.conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
    evt.p_link_ctx  = p_client;
 NRF_LOG_INFO("on_write################################\n");
    if ((p_evt_write->handle == p_gfp->keybase_pair_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
           NRF_LOG_INFO("keybase_pair_ccchandles################################%d&  %d\n",ble_srv_is_notification_enabled(p_evt_write->data),ble_srv_is_indication_enabled(p_evt_write->data));
 
           

    }
    else if ((p_evt_write->handle == p_gfp->passkey_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
         NRF_LOG_INFO("passkey_ccchandles################################\n");
    }
     else if ((p_evt_write->handle == p_gfp->addi_data_handles.cccd_handle) &&
        (p_evt_write->len == 2))
    {
        //if (p_client != NULL)
        //{
        //    if (ble_srv_is_notification_enabled(p_evt_write->data))
        //    {
        //        p_client->is_notification_enabled = true;
        //        evt.type                          = BLE_GFP_EVT_COMM_STARTED;
        //    }
        //    else
        //    {
        //        p_client->is_notification_enabled = false;
        //        evt.type                          = BLE_GFP_EVT_COMM_STOPPED;
        //    }

        //    if (p_gfp->data_handler != NULL)
        //    {
        //        p_gfp->data_handler(&evt);
        //    }

        //}
      NRF_LOG_INFO("addi_data_ccchandles################################%d&  %d\n",ble_srv_is_notification_enabled(p_evt_write->data),ble_srv_is_indication_enabled(p_evt_write->data));
    }
    else if ((p_evt_write->handle == p_gfp->keybase_pair_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("keybase_pair_handles################################\n");
                      

    }
    else if ((p_evt_write->handle == p_gfp->passkey_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("passkey_handles################################\n");
                      

    }
        else if ((p_evt_write->handle == p_gfp->account_key_handles.value_handle) )
    {
        //evt.type                  = BLE_GFP_EVT_RX_DATA;
        //evt.params.rx_data.p_data = p_evt_write->data;
        //evt.params.rx_data.length = p_evt_write->len;

        //p_gfp->data_handler(&evt);
         NRF_LOG_INFO("account_key_handles################################\n");
                      

    }
    else
    {
        // Do Nothing. This event is not relevant for this service.
    }
}

#if 0
/**@brief Function for handling the @ref BLE_GATTS_EVT_HVN_TX_COMPLETE event from the SoftDevice.
 *
 * @param[in] p_gfp     Nordic UART Service structure.
 * @param[in] p_ble_evt Pointer to the event received from BLE stack.
 */
static void on_hvx_tx_complete(ble_gfp_t * p_gfp, ble_evt_t const * p_ble_evt)
{
    ret_code_t                 err_code;
    ble_gfp_evt_t              evt;
    ble_gfp_client_context_t * p_client;

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage,
                                 p_ble_evt->evt.gatts_evt.conn_handle,
                                 (void *) &p_client);
    if (err_code != NRF_SUCCESS)
    {
        NRF_LOG_ERROR("Link context for 0x%02X connection handle could not be fetched.",
                      p_ble_evt->evt.gatts_evt.conn_handle);
        return;
    }

    if ((p_client->is_notification_enabled) && (p_gfp->data_handler != NULL))
    {
        memset(&evt, 0, sizeof(ble_gfp_evt_t));
        evt.type        = BLE_GFP_EVT_TX_RDY;
        evt.p_gfp       = p_gfp;
        evt.conn_handle = p_ble_evt->evt.gatts_evt.conn_handle;
        evt.p_link_ctx  = p_client;

        p_gfp->data_handler(&evt);
    }
}
#endif

void ble_gfp_on_ble_evt(ble_evt_t const * p_ble_evt, void * p_context)
{
    if ((p_context == NULL) || (p_ble_evt == NULL))
    {
        return;
    }

    ble_gfp_t * p_gfp = (ble_gfp_t *)p_context;

    switch (p_ble_evt->header.evt_id)
    {
        case BLE_GAP_EVT_CONNECTED:
            //on_connect(p_gfp, p_ble_evt);
            break;

        case BLE_GATTS_EVT_WRITE:
            on_write(p_gfp, p_ble_evt);
            break;

        case BLE_GATTS_EVT_HVN_TX_COMPLETE:
            //on_hvx_tx_complete(p_gfp, p_ble_evt);
            break;

        default:
            // No implementation needed.
            break;
    }
}


uint32_t ble_gfp_init(ble_gfp_t * p_gfp, ble_gfp_init_t const * p_gfp_init)
{
    ret_code_t            err_code;
    ble_uuid_t            ble_uuid;
    ble_uuid128_t         gfp_character_base_uuid = GFP_CHARACTERISTIC_BASE_UUID;
    ble_add_char_params_t add_char_params;
    uint8_t               character_uuid_type=0;
    uint8_t model_id[] = {0x2a, 0x41, 0x0b}; // model_id
    VERIFY_PARAM_NOT_NULL(p_gfp);
    VERIFY_PARAM_NOT_NULL(p_gfp_init);
 NRF_LOG_INFO("ble_gfp_init################################\n");    // Initialize the service structure.
    p_gfp->data_handler = p_gfp_init->data_handler;
    

    /**@snippet [Adding proprietary Service to the SoftDevice] 
    // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&gfp_base_uuid, &p_gfp->uuid_type);
    VERIFY_SUCCESS(err_code);*/
   // Add service
    BLE_UUID_BLE_ASSIGN(ble_uuid, GFP_SERVICE_UUID);

    //ble_uuid.type = p_gfp->uuid_type;
    //ble_uuid.uuid = BLE_UUID_GFP_SERVICE;
    p_gfp->uuid_type = ble_uuid.type;
    // Add the service.
    err_code = sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY,
                                        &ble_uuid,
                                        &p_gfp->service_handle);
    /**@snippet [Adding proprietary Service to the SoftDevice] */
    VERIFY_SUCCESS(err_code);


     // Add a custom base UUID.
    err_code = sd_ble_uuid_vs_add(&gfp_character_base_uuid, &character_uuid_type);
    VERIFY_SUCCESS(err_code);
    // Add the RX Characteristic.
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid                     = BLE_UUID_GFP_MODEL_ID_CHARACTERISTIC;
    add_char_params.uuid_type                = character_uuid_type;
    add_char_params.max_len                  = 3;
    add_char_params.init_len                 = 3;
    add_char_params.p_init_value             = model_id;
    //add_char_params.is_var_len               = true;
    //add_char_params.char_props.write         = 1;
    add_char_params.char_props.read = 1;
    //add_char_params.char_props.write_wo_resp = 1;
    add_char_params.read_access  = SEC_OPEN;
    add_char_params.write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->model_id_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }

    // Add the key base pairing Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_KEY_BASED_PAIRING_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = BLE_GFP_MAX_TX_CHAR_LEN;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->keybase_pair_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }

     // Add the passkey  Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_PASSKEY_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = BLE_GFP_MAX_TX_CHAR_LEN;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->passkey_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }

    // Add the account key  Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_ACCOUNT_KEY_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = BLE_GFP_MAX_TX_CHAR_LEN;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    //add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    //add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->account_key_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }


    // Add the addi data Characteristic.
    /**@snippet [Adding proprietary characteristic to the SoftDevice] */
    memset(&add_char_params, 0, sizeof(add_char_params));
    add_char_params.uuid              = BLE_UUID_GFP_ADDI_DATA_CHARACTERISTIC;
    add_char_params.uuid_type         = character_uuid_type;
    add_char_params.max_len           = BLE_GFP_MAX_TX_CHAR_LEN;
    add_char_params.init_len          = sizeof(uint8_t);
    add_char_params.is_var_len        = true;
    add_char_params.char_props.notify = 1;
    add_char_params.char_props.write  = 1;

    add_char_params.read_access       = SEC_OPEN;
    add_char_params.write_access      = SEC_OPEN;
    add_char_params.cccd_write_access = SEC_OPEN;

    err_code = characteristic_add(p_gfp->service_handle, &add_char_params, &p_gfp->addi_data_handles);
    if (err_code != NRF_SUCCESS)
    {
        return err_code;
    }
}

#if 0
uint32_t ble_gfp_data_send(ble_gfp_t * p_gfp,
                           uint8_t   * p_data,
                           uint16_t  * p_length,
                           uint16_t    conn_handle)
{
    ret_code_t                 err_code;
    ble_gatts_hvx_params_t     hvx_params;
    ble_gfp_client_context_t * p_client;

    VERIFY_PARAM_NOT_NULL(p_gfp);

    err_code = blcm_link_ctx_get(p_gfp->p_link_ctx_storage, conn_handle, (void *) &p_client);
    VERIFY_SUCCESS(err_code);

    if ((conn_handle == BLE_CONN_HANDLE_INVALID) || (p_client == NULL))
    {
        return NRF_ERROR_NOT_FOUND;
    }

    if (!p_client->is_notification_enabled)
    {
        return NRF_ERROR_INVALID_STATE;
    }

    if (*p_length > BLE_GFP_MAX_DATA_LEN)
    {
        return NRF_ERROR_INVALID_PARAM;
    }

    memset(&hvx_params, 0, sizeof(hvx_params));

    hvx_params.handle = p_gfp->tx_handles.value_handle;
    hvx_params.p_data = p_data;
    hvx_params.p_len  = p_length;
    hvx_params.type   = BLE_GATT_HVX_NOTIFICATION;

    return sd_ble_gatts_hvx(conn_handle, &hvx_params);
}

#endif

