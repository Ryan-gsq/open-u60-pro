/* Small standalone supervisor for the proposed metadata-only smoke commands.
 * A child is never reaped before its timeout signal, preventing PID reuse. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static double now(void) { struct timespec t; if(clock_gettime(CLOCK_MONOTONIC,&t)) exit(125); return t.tv_sec+t.tv_nsec/1e9; }
int main(int argc,char **argv) {
    if(argc<3) return 64;
    char *end;long seconds=strtol(argv[1],&end,10);
    if(*end || seconds<1 || seconds>30) return 64;
    pid_t child=fork();if(child<0)return 125;
    if(!child){if(setpgid(0,0))_exit(125);execv(argv[2],argv+2);_exit(127);}
    /* The child sets its own group before exec; parent also closes the race. */
    if(setpgid(child,child)<0 && errno!=EACCES && errno!=ESRCH){kill(child,SIGKILL);waitpid(child,NULL,0);return 125;}
    double deadline=now()+seconds;int timed_out=0,stage=0,status;
    for(;;){
        pid_t r=waitpid(child,&status,WNOHANG);
        if(r==child)return timed_out?124:(WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status));
        if(r<0 && errno!=EINTR)return 125;
        if(now()>=deadline){
            timed_out=1;kill(-child,stage?SIGKILL:SIGTERM);stage=1;deadline=now()+2;
        }
        struct timespec delay={0,10000000};nanosleep(&delay,NULL);
    }
}
