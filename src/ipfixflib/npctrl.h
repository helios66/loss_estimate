#ifndef NPCTRL_H
#define NPCTRL_H

extern void  ipfix_init(void);
extern void *ipfix_start(void *mapi_ctxt,
			 ifp_rec_type_t rec_type, 
			 char *transport_name,
			 char *string_template,
			 struct mapid_hw_info *hwinfo);
extern void  ipfix_shutdown(void *npctxt);
#endif
