#include <assert.h>
#include <stdio.h>
#include <euicc-driver-loader.h>
int apdu_init_count, apdu_fini_count, http_init_count, http_fini_count, fail_apdu;
int main(void){
 assert(euicc_driver_init("fakeapdu","fakehttp")==-1);
 assert(apdu_init_count==1 && apdu_fini_count==1 && http_init_count==1 && http_fini_count==0);
 euicc_driver_fini();euicc_driver_fini();assert(apdu_fini_count==1);
 fail_apdu=1;
 assert(euicc_driver_init("fakeapdu","fakehttp")==-1);
 euicc_driver_fini();assert(apdu_init_count==2 && apdu_fini_count==1 && http_init_count==1 && http_fini_count==0);
 puts("PASS driver-loader HTTP init failure unwinds APDU once; APDU init failure and repeated fini are safe");return 0;
}
