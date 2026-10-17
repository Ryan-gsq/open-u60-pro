/* Off-device tests: real GLib/libqmi input objects; transport and reply mocks.
 * No actual QRTR or modem functions are called by this executable. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "qmi_common.h"
#include <driver.h>
extern const struct euicc_driver driver_if;
static const char *fault;
#ifndef BASELINE
static int fail_calloc;
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
 if (fail_calloc) { fail_calloc=0; return NULL; }
 return __real_calloc(n,size);
}
#endif
static int bus_calls, created, destroyed, release_calls, device_close_calls;
static int channel_calls, apdu_calls, channel_close_calls, outputs;
static GList *nodes;
static GObject *node_obj;
static int is(const char *s) { return fault && !strcmp(fault,s); }
static void err(GError **e) { if (!is("null-no-error")) g_set_error_literal(e,G_IO_ERROR,G_IO_ERROR_FAILED,"injected test failure"); }
static void finalized(gpointer data,GObject *obj) { (void)data;(void)obj;destroyed++; }
static gpointer track(GObject *obj) { created++;g_object_weak_ref(obj,finalized,NULL);return obj; }
QrtrBus *qrtr_bus_new_sync(GMainContext *c,GError **e) {
 (void)c;bus_calls++;
 if(is("bus") || is("null-no-error")){err(e);return NULL;}
 return track(g_object_new(G_TYPE_OBJECT,NULL));
}
GList *qrtr_bus_peek_nodes(QrtrBus *b) { (void)b;return is("no-service") ? NULL : nodes; }
guint32 qrtr_node_get_id(QrtrNode *n) { (void)n;if(is("wrong-node"))return 4; if(is("ambiguous"))return 3; if(is("selected-not-first"))return (GObject*)n==node_obj?4:3; return (GObject*)n==node_obj?3:4; }
gint32 qrtr_node_lookup_port(QrtrNode *n,guint32 service) { (void)n;assert(service==QMI_SERVICE_UIM);return is("no-uim") ? -1 : 86; }
QmiDevice *qmi_device_new_from_node_sync(QrtrNode *n,GMainContext *c,GError **e) {
 (void)n;(void)c;if(is("device")){err(e);return NULL;}
 return track(g_object_new(QMI_TYPE_DEVICE,NULL));
}
gboolean qmi_device_open_sync(QmiDevice *d,QmiDeviceOpenFlags f,GMainContext *c,GError **e) {
 (void)d;(void)c;assert(f==QMI_DEVICE_OPEN_FLAGS_NONE);
 if(is("open") || is("open-false-no-error")){if(is("open"))err(e);return FALSE;}return TRUE;
}
QmiClient *qmi_device_allocate_client_sync(QmiDevice *d,GMainContext *c,GError **e) {
 (void)c;if(is("allocate")){err(e);return NULL;}
 return track(g_object_new(QMI_TYPE_CLIENT_UIM,QMI_CLIENT_DEVICE,d,QMI_CLIENT_SERVICE,QMI_SERVICE_UIM,NULL));
}
gboolean qmi_device_release_client_sync(QmiDevice *d,QmiClient *u,GMainContext *c,GError **e) {
 assert(d && u && c);release_calls++;if(is("release")){err(e);return FALSE;}return TRUE;
}
gboolean qmi_device_close_sync(QmiDevice *d,GMainContext *c,GError **e) {
 assert(d && c);device_close_calls++;if(is("device-close")){err(e);return FALSE;}return TRUE;
}
typedef struct { int kind; GArray *data; } Reply;
static void *reply(int kind) { Reply *r=calloc(1,sizeof(*r));assert(r);r->kind=kind;outputs++;return r; }
static void unreply(void *p){Reply *r=p;assert(r);if(r->data)g_array_unref(r->data);free(r);outputs--;}
QmiMessageUimOpenLogicalChannelOutput *qmi_client_uim_open_logical_channel_sync(QmiClientUim *u,QmiMessageUimOpenLogicalChannelInput *i,GMainContext *c,GError **e) {
 guint8 slot=0;assert(u && c);assert(qmi_message_uim_open_logical_channel_input_get_slot(i,&slot,NULL));assert(slot==2);channel_calls++;
 if(is("channel-null")){err(e);return NULL;}return reply(1);
}
gboolean qmi_message_uim_open_logical_channel_output_get_result(QmiMessageUimOpenLogicalChannelOutput *o,GError **e) {
 assert(o);if(is("channel-result")){err(e);return FALSE;}return TRUE;
}
gboolean qmi_message_uim_open_logical_channel_output_get_channel_id(QmiMessageUimOpenLogicalChannelOutput *o,guint8 *v,GError **e) {
 assert(o);if(is("channel-id")){err(e);return FALSE;}*v=is("channel-zero")?0:7;return TRUE;
}
void qmi_message_uim_open_logical_channel_output_unref(QmiMessageUimOpenLogicalChannelOutput *o){unreply(o);}
QmiMessageUimSendApduOutput *qmi_client_uim_send_apdu_sync(QmiClientUim *u,QmiMessageUimSendApduInput *i,GMainContext *c,GError **e) {
 guint8 slot=0,ch=0;assert(u && c);assert(qmi_message_uim_send_apdu_input_get_slot(i,&slot,NULL));assert(slot==2);
 assert(qmi_message_uim_send_apdu_input_get_channel_id(i,&ch,NULL));assert(ch==7);apdu_calls++;
 if(is("apdu-null")){err(e);return NULL;}return reply(2);
}
gboolean qmi_message_uim_send_apdu_output_get_result(QmiMessageUimSendApduOutput *o,GError **e){assert(o);if(is("apdu-result")){err(e);return FALSE;}return TRUE;}
gboolean qmi_message_uim_send_apdu_output_get_apdu_response(QmiMessageUimSendApduOutput *o,GArray **a,GError **e){
 if(is("apdu-response")){err(e);return FALSE;}Reply *r=(Reply*)o;unsigned char bytes[]={0x90,0x00};
 r->data=g_array_new(FALSE,FALSE,1);if(!is("apdu-empty"))g_array_append_vals(r->data,bytes,2);*a=r->data;return TRUE;
}
void qmi_message_uim_send_apdu_output_unref(QmiMessageUimSendApduOutput *o){unreply(o);}
QmiMessageUimLogicalChannelOutput *qmi_client_uim_logical_channel_sync(QmiClientUim *u,QmiMessageUimLogicalChannelInput *i,GMainContext *c,GError **e){
 guint8 slot=0,ch=0;channel_close_calls++;
#ifdef BASELINE
 (void)u;(void)i;(void)c;err(e);return NULL;
#else
 assert(u && c);assert(qmi_message_uim_logical_channel_input_get_slot(i,&slot,NULL));assert(slot==2);
 assert(qmi_message_uim_logical_channel_input_get_channel_id(i,&ch,NULL));assert(ch==7);
 if(is("close-null") || is("null-no-error")){err(e);return NULL;}return reply(3);
#endif
}
gboolean qmi_message_uim_logical_channel_output_get_result(QmiMessageUimLogicalChannelOutput *o,GError **e){assert(o);if(is("close-result")){err(e);return FALSE;}return TRUE;}
void qmi_message_uim_logical_channel_output_unref(QmiMessageUimLogicalChannelOutput *o){unreply(o);}

#ifdef BASELINE
/* Make malloc's permitted nonzero contents deterministic, not a fake hardware condition. */
void *poison_malloc(size_t n){void *p=malloc(n);if(p)memset(p,1,n);return p;}
int main(void){
 struct euicc_apdu_interface iface={0};assert(driver_if.init(&iface)==0);driver_if.fini(&iface);
 assert(bus_calls==0 && channel_close_calls==1);
 puts("BASELINE REPRODUCED: init/fini without connect attempted one Close Logical Channel using uninitialized state");return 0;
}
#else
static void counters_reset(void){bus_calls=created=destroyed=release_calls=device_close_calls=channel_calls=apdu_calls=channel_close_calls=outputs=0;}
static void run(const char *f){
 fault=f;counters_reset();struct euicc_apdu_interface iface={0};struct euicc_ctx ctx={0};ctx.apdu.interface=&iface;
 assert(driver_if.init(&iface)==0);struct qmi_data *p=iface.userdata;
 assert(p->lastChannelId==-1 && p->uimClient==NULL && p->context==NULL);
 if(is("init-only")){driver_if.fini(&iface);driver_if.fini(&iface);assert(!bus_calls && !channel_close_calls);puts("PASS init-only + repeated fini: zero transport calls");return;}
 int res=iface.connect(&ctx);
 int connection_failure=is("bus")||is("null-no-error")||is("no-service")||is("wrong-node")||is("no-uim")||is("ambiguous")||is("device")||is("open")||is("open-false-no-error")||is("allocate");
 if(connection_failure){assert(res==-1);assert(!p->context && !p->device && !p->qrtrBus && !p->uimClient);}
 else {
  assert(res==0);assert(iface.connect(&ctx)==-1);assert(bus_calls==1);
  unsigned char aid[]={0x01,0x02};int ch=iface.logic_channel_open(&ctx,aid,2);
  int channel_failure=is("channel-null")||is("channel-result")||is("channel-id")||is("channel-zero");
  if(channel_failure){assert(ch==-1 && p->lastChannelId==-1 && p->channelStateUnknown);assert(iface.logic_channel_open(&ctx,aid,2)==-1);assert(channel_calls==1);}
  else {
   assert(ch==7);assert(iface.logic_channel_open(&ctx,aid,2)==-1);assert(channel_calls==1);
   uint8_t *rx=(void*)1;uint32_t len=123;unsigned char apdu[]={0,1};
   int txres=iface.transmit(&ctx,&rx,&len,apdu,2);
   if(is("apdu-null")||is("apdu-result")||is("apdu-response")){assert(txres==-1 && rx==NULL && len==0);}
   else if(is("apdu-empty")){assert(txres==0 && rx==NULL && len==0);}
   else {assert(txres==0 && len==2 && rx[0]==0x90 && rx[1]==0);free(rx);}
   iface.logic_channel_close(&ctx,8);assert(channel_close_calls==0);
   if(!is("implicit-close")){iface.logic_channel_close(&ctx,7);iface.logic_channel_close(&ctx,7);assert(channel_close_calls==1);}
  }
 }
 iface.disconnect(&ctx);iface.disconnect(&ctx);if(p->channelStateUnknown)assert(iface.connect(&ctx)==-1);driver_if.fini(&iface);driver_if.fini(&iface);
 assert(outputs==0 && created==destroyed);
 if(connection_failure)assert(!channel_calls && !channel_close_calls && !release_calls);
 else {assert(release_calls==1 && device_close_calls==1);}
 printf("PASS %s: objects=%d/%d replies=%d close=%d release=%d\n",f,created,destroyed,outputs,channel_close_calls,release_calls);
}
static void selections(void){
 const char *invalid[]={"","-1","+1"," 1","1 ","1x","4294967295","999999999999999999999999",NULL};
 for(int kind=0;kind<2;kind++){
  for(int n=-1;n<8;n++){
   setenv("LPAC_APDU_QMI_QRTR_NODE","3",1);setenv("LPAC_APDU_QMI_UIM_SLOT","2",1);
   const char *name=kind?"LPAC_APDU_QMI_UIM_SLOT":"LPAC_APDU_QMI_QRTR_NODE";
   if(n==-1)unsetenv(name);else setenv(name,invalid[n],1);
   struct euicc_apdu_interface iface={0};struct euicc_ctx ctx={0};ctx.apdu.interface=&iface;
   counters_reset();assert(driver_if.init(&iface)==0);assert(iface.connect(&ctx)==-1);driver_if.fini(&iface);assert(!bus_calls);
  }
 }
 for(int n=0;n<2;n++){
  setenv("LPAC_APDU_QMI_QRTR_NODE","3",1);setenv("LPAC_APDU_QMI_UIM_SLOT",n?"256":"0",1);
  struct euicc_apdu_interface iface={0};struct euicc_ctx ctx={0};ctx.apdu.interface=&iface;counters_reset();
  assert(driver_if.init(&iface)==0);assert(iface.connect(&ctx)==-1);driver_if.fini(&iface);assert(!bus_calls);
 }
 puts("PASS 20 unset/invalid node/slot selections: zero transport calls");
}
int main(void){
 g_log_set_always_fatal(G_LOG_LEVEL_ERROR|G_LOG_LEVEL_CRITICAL|G_LOG_LEVEL_WARNING);
 node_obj=g_object_new(G_TYPE_OBJECT,NULL);nodes=g_list_append(NULL,node_obj);GObject *other=g_object_new(G_TYPE_OBJECT,NULL);nodes=g_list_append(nodes,other);
 struct euicc_apdu_interface failed_iface={0};
 fail_calloc=1;assert(driver_if.init(&failed_iface)==-1);driver_if.fini(&failed_iface);assert(failed_iface.userdata==NULL);
 puts("PASS init allocation failure: no transport calls");
 selections();setenv("LPAC_APDU_QMI_QRTR_NODE","3",1);setenv("LPAC_APDU_QMI_UIM_SLOT","2",1);
 const char *cases[]={"init-only","bus","null-no-error","no-service","wrong-node","no-uim","ambiguous","device","open","open-false-no-error","allocate","channel-null","channel-result","channel-id","channel-zero","apdu-null","apdu-result","apdu-response","apdu-empty","close-null","close-result","release","device-close","implicit-close","selected-not-first","success",NULL};
 for(int i=0;cases[i];i++)run(cases[i]);
 g_list_free(nodes);g_object_unref(node_obj);g_object_unref(other);puts("ALL MOCK FAILURE TESTS PASSED");return 0;
}
#endif
