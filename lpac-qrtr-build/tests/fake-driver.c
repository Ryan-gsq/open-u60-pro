#include <assert.h>
#include <stdlib.h>
#include <driver.h>
#include <euicc/interface.h>
extern int apdu_init_count, apdu_fini_count, http_init_count, http_fini_count, fail_apdu;
#ifdef FAKE_APDU
static int init(void *p){struct euicc_apdu_interface *i=p;apdu_init_count++;if(fail_apdu)return -1;i->userdata=malloc(1);assert(i->userdata);return 0;}
static void fini(void *p){struct euicc_apdu_interface *i=p;assert(i->userdata);free(i->userdata);i->userdata=NULL;apdu_fini_count++;}
DRIVER_INTERFACE={.type=DRIVER_APDU,.name="fakeapdu",.init=init,.fini=fini};
#else
static int init(void *p){(void)p;http_init_count++;return -1;}
static void fini(void *p){(void)p;http_fini_count++;}
DRIVER_INTERFACE={.type=DRIVER_HTTP,.name="fakehttp",.init=init,.fini=fini};
#endif
