#ifndef IFP_PRIV_H
#define IFP_PRIV_H

typedef enum { 
  rec_type_undef, 
  rec_type_ipfix, 
  rec_type_nf_v5, 
  rec_type_nf_v9 
} ifp_rec_type_t;

extern void ifp_write_shm(const void *ctxt, 
			  const void *buffer, u_int32_t buf_len);

extern mapi_offline_device_status_t
ifp_get_offline_device_status(const void *ctxt);

#endif
