libKernels := \
__cxa_finalize \
free \
calloc \
malloc \
memcpy \
memset \
_rtld_get_stack_prot \
snprintf \
abort \
_Unwind_ForcedUnwind \
exit \
_malloc_thread_cleanup \
_Unwind_GetCFA \
_malloc_prefork \
_malloc_postfork \
sceLibcMspaceCalloc \
sceLibcMspaceFree \
strlen \
strncmp \
sceLibcMspaceMalloc \
_malloc_init \
strcmp \
_Getptoupper \
index \
bcopy \
strncpy \
strsep \
strlcat \
strlcpy \
memchr \
_getprogname \
strerror \
fprintf \
flsl \
printf \
strncat \
puts \
malloc_stats \
perror \
__error \
pthread_setaffinity_np \
pthread_getaffinity_np \
pthread_attr_destroy \
pthread_attr_get_np \
pthread_attr_getdetachstate \
pthread_attr_getguardsize \
pthread_attr_getinheritsched \
pthread_attr_getschedparam \
pthread_attr_getschedpolicy \
pthread_attr_getscope \
pthread_attr_getstack \
pthread_attr_getstackaddr \
pthread_attr_getstacksize \
pthread_attr_init \
pthread_attr_setcreatesuspend_np \
pthread_attr_setdetachstate \
pthread_attr_setguardsize \
pthread_attr_setinheritsched \
pthread_attr_setschedparam \
pthread_attr_setschedpolicy \
pthread_attr_setscope \
pthread_attr_setstack \
pthread_attr_setstackaddr \
pthread_attr_setstacksize \
pthread_attr_setaffinity_np \
pthread_attr_getaffinity_np \
pthread_barrier_destroy \
pthread_barrier_init \
pthread_barrier_wait \
pthread_barrierattr_destroy \
pthread_barrierattr_getpshared \
pthread_barrierattr_init \
pthread_barrierattr_setpshared \
pthread_setcanceltype \
pthread_testcancel \
__pthread_cleanup_pop_imp \
pthread_cleanup_push \
pthread_cleanup_pop \
pthread_getconcurrency \
pthread_setconcurrency \
pthread_cond_init \
pthread_cond_destroy \
pthread_cond_wait \
pthread_cond_timedwait \
pthread_cond_signal \
pthread_cond_broadcast \
pthread_cond_signalto_np \
pthread_condattr_init \
pthread_condattr_destroy \
pthread_condattr_getclock \
pthread_condattr_setclock \
pthread_condattr_getpshared \
pthread_condattr_setpshared \
pthread_create \
pthread_create_name_np \
pthread_exit \
__pthread_cxa_finalize \
fork \
pthread_getprio \
pthread_getcpuclockid \
pthread_getschedparam \
pthread_set_name_np \
pthread_kill \
pthread_main_np \
pthread_multi_np \
pthread_mutex_init \
pthread_mutex_lock \
pthread_mutex_timedlock \
pthread_mutex_trylock \
pthread_mutex_setyieldloops_np \
pthread_mutex_destroy \
pthread_mutex_unlock \
pthread_mutex_getprioceiling \
pthread_mutex_setprioceiling \
pthread_mutex_getyieldloops_np \
pthread_mutex_isowned_np \
pthread_mutexattr_init \
pthread_mutexattr_setkind_np \
pthread_mutexattr_getkind_np \
pthread_mutexattr_settype \
pthread_mutexattr_gettype \
pthread_mutexattr_destroy \
pthread_mutexattr_getpshared \
pthread_mutexattr_setpshared \
pthread_mutexattr_getprotocol \
pthread_mutexattr_setprotocol \
pthread_mutexattr_getprioceiling \
pthread_mutexattr_setprioceiling \
pthread_once \
pthread_spin_init \
pthread_spin_destroy \
pthread_spin_trylock \
pthread_spin_lock \
pthread_spin_unlock \
pthread_resume_np \
pthread_resume_all_np \
pthread_rwlock_destroy \
pthread_rwlock_init \
pthread_rwlock_rdlock \
pthread_rwlock_timedrdlock \
pthread_rwlock_reltimedrdlock_np \
pthread_rwlock_tryrdlock \
pthread_rwlock_wrlock \
pthread_rwlock_timedwrlock \
pthread_rwlock_reltimedwrlock_np \
pthread_rwlock_unlock \
pthread_rwlockattr_destroy \
pthread_rwlockattr_getpshared \
pthread_rwlockattr_init \
pthread_rwlockattr_setpshared \
pthread_self \
pthread_setprio \
pthread_setschedparam \
pause \
sigprocmask \
sigsuspend \
raise \
sigaction \
setcontext \
swapcontext \
pthread_single_np \
pthread_key_create \
accept \
aio_suspend \
close \
connect \
creat \
fcntl \
fsync \
msync \
nanosleep \
open \
openat \
poll \
pselect \
read \
readv \
recvfrom \
recvmsg \
select \
sendmsg \
sendto \
sleep \
system \
tcdrain \
usleep \
wait \
wait3 \
wait4 \
waitpid \
write \
writev \
pthread_suspend_np \
pthread_suspend_all_np \
pthread_switch_delete_np \
syscall \
_read \
_write \
_open \
_close \
_wait4 \
link \
unlink \
chdir \
fchdir \
chmod \
chown \
getfsstat \
getpid \
mount \
unmount \
setuid \
getuid \
geteuid \
_recvmsg \
_sendmsg \
_recvfrom \
_accept \
getpeername \
getsockname \
access \
chflags \
fchflags \
sync \
kill \
stat \
getppid \
lstat \
dup \
getegid \
profil \
ktrace \
getgid \
sigpending \
sigaltstack \
ioctl \
revoke \
symlink \
readlink \
execve \
umask \
chroot \
fstat \
munmap \
mprotect \
madvise \
mincore \
getgroups \
setgroups \
setpgid \
setitimer \
swapon \
getitimer \
getdtablesize \
dup2 \
_fcntl \
setpriority \
socket \
_connect \
getpriority \
bind \
setsockopt \
listen \
gettimeofday \
getrusage \
getsockopt \
settimeofday \
fchown \
fchmod \
setreuid \
setregid \
rename \
flock \
_sendto \
shutdown \
socketpair \
mkdir \
rmdir \
utimes \
getrlimit \
setrlimit \
setsid \
getdirentries \
statfs \
fstatfs \
sysarch \
setegid \
seteuid \
pathconf \
fpathconf \
mlock \
munlock \
futimes \
clock_gettime \
clock_settime \
clock_getres \
ktimer_create \
ktimer_delete \
ktimer_settime \
ktimer_gettime \
ktimer_getoverrun \
issetugid \
lchown \
aio_read \
aio_write \
getdents \
lchmod \
lutimes \
preadv \
pwritev \
kldload \
kldunload \
kldfind \
kldnext \
kldstat \
kldfirstmod \
getsid \
aio_return \
aio_cancel \
aio_error \
mlockall \
munlockall \
__getcwd \
sched_setparam \
sched_getparam \
sched_setscheduler \
sched_getscheduler \
sched_yield \
sched_get_priority_max \
sched_get_priority_min \
sched_rr_get_interval \
utrace \
sendfile \
kldsym \
aio_waitcomplete \
kqueue \
kevent \
nmount \
kenv \
lchflags \
uuidgen \
ksem_close \
ksem_post \
ksem_wait \
ksem_trywait \
ksem_init \
ksem_open \
ksem_unlink \
ksem_getvalue \
ksem_destroy \
ksem_timedwait \
sigqueue \
kmq_open \
kmq_setattr \
kmq_timedreceive \
kmq_timedsend \
kmq_notify \
kmq_unlink \
aio_fsync \
rtprio_thread \
shm_open \
shm_unlink \
cpuset \
cpuset_setid \
cpuset_getid \
cpuset_getaffinity \
cpuset_setaffinity \
fchmodat \
fchownat \
fstatat \
futimesat \
linkat \
mkdirat \
_openat \
renameat \
symlinkat \
unlinkat \
debug_init \
mdbg_call \
is_in_sandbox \
get_authinfo \
mdbg_service \
_exit \
start \
_sceKernelRtldSetApplicationHeapAPI \
__tls_get_addr \
sceKernelReportUnpatchedFunctionCall \
rtld_printf \
__stack_chk_fail \
rfork_thread \
sigsetjmp \
siglongjmp \
amd64_set_fsbase \
getcontext \
pipe \
ptrace \
reboot \
setlogin \
sigreturn \
vfork \
__elf_phdr_match_addr \
execvp \
execv \
_execvpe \
getlogin \
getlogin_r \
getpagesize \
sem_init \
sem_open \
sem_close \
sem_unlink \
sem_destroy \
sem_getvalue \
sem_trywait \
sem_timedwait \
sem_wait \
sem_post \
signal \
sigaddset \
sigdelset \
sigemptyset \
sigfillset \
sigismember \
sysconf \
sysctl \
sysctlbyname \
sysctlnametomib \
tcgetattr \
tcsetattr \
tcsetpgrp \
tcgetpgrp \
tcgetsid \
tcsetsid \
tcsendbreak \
tcflush \
tcflow \
inet_ntop \
inet_pton \
htonl \
htons \
ntohl \
ntohs \
recv \
send \
lseek \
mmap \
pread \
pwrite \
truncate \
sceKernelDebugRaiseException \
sceKernelDebugRaiseExceptionOnReleaseMode \
scePthreadAtfork \
scePthreadAttrDestroy \
scePthreadAttrGetstack \
scePthreadAttrGetstacksize \
scePthreadAttrGetguardsize \
scePthreadAttrGetstackaddr \
scePthreadAttrGetdetachstate \
scePthreadAttrInit \
scePthreadAttrSetstacksize \
scePthreadAttrSetguardsize \
scePthreadAttrSetstack \
scePthreadAttrSetstackaddr \
scePthreadAttrSetdetachstate \
scePthreadBarrierInit \
scePthreadBarrierDestroy \
scePthreadBarrierWait \
scePthreadBarrierattrDestroy \
scePthreadBarrierattrGetpshared \
scePthreadBarrierattrInit \
scePthreadBarrierattrSetpshared \
scePthreadCondattrDestroy \
scePthreadCondattrGetclock \
scePthreadCondattrGetpshared \
scePthreadCondattrInit \
scePthreadCondattrSetclock \
scePthreadCondattrSetpshared \
scePthreadCondBroadcast \
scePthreadCondInit \
scePthreadCondDestroy \
scePthreadCondSignal \
scePthreadCondSignalto \
scePthreadCondTimedwait \
scePthreadCondWait \
scePthreadCreate \
scePthreadDetach \
scePthreadEqual \
scePthreadExit \
scePthreadGetcpuclockid \
scePthreadJoin \
scePthreadKeyCreate \
scePthreadKeyDelete \
scePthreadMutexattrInit \
scePthreadMutexattrDestroy \
scePthreadMutexattrGetpshared \
scePthreadMutexattrGettype \
scePthreadMutexattrSettype \
scePthreadMutexattrSetpshared \
scePthreadMutexInit \
scePthreadMutexDestroy \
scePthreadMutexLock \
scePthreadMutexTrylock \
scePthreadMutexTimedlock \
scePthreadMutexUnlock \
scePthreadOnce \
scePthreadRwlockInit \
scePthreadRwlockDestroy \
scePthreadRwlockRdlock \
scePthreadRwlockTimedrdlock \
scePthreadRwlockTimedwrlock \
scePthreadRwlockTryrdlock \
scePthreadRwlockTrywrlock \
scePthreadRwlockUnlock \
scePthreadRwlockWrlock \
scePthreadRwlockattrDestroy \
scePthreadRwlockattrGetpshared \
scePthreadRwlockattrInit \
scePthreadRwlockattrSetpshared \
scePthreadSelf \
scePthreadSetspecific \
scePthreadCancel \
scePthreadSetcancelstate \
scePthreadSetcanceltype \
scePthreadTestcancel \
scePthreadGetprio \
scePthreadGetschedparam \
scePthreadSetprio \
scePthreadYield \
scePthreadMutexattrGetprioceiling \
scePthreadMutexattrSetprioceiling \
scePthreadMutexGetprioceiling \
scePthreadMutexSetprioceiling \
scePthreadMutexattrGetprotocol \
scePthreadMutexattrSetprotocol \
scePthreadAttrGetinheritsched \
scePthreadAttrGetschedparam \
scePthreadAttrGetschedpolicy \
scePthreadAttrGetscope \
scePthreadAttrSetinheritsched \
scePthreadAttrSetschedparam \
scePthreadAttrSetschedpolicy \
scePthreadAttrSetscope \
scePthreadSetschedparam \
scePthreadGetconcurrency \
scePthreadSetconcurrency \
scePthreadAttrGet \
scePthreadAttrGetaffinity \
scePthreadAttrSetaffinity \
scePthreadGetaffinity \
scePthreadSetaffinity \
scePthreadRename \
scePthreadGetthreadid \
scePthreadSetName \
scePthreadAttrSetcreatesuspend \
scePthreadMain \
scePthreadMulti \
scePthreadMutexattrGetkind \
scePthreadMutexattrSetkind \
scePthreadResumeAll \
scePthreadResume \
scePthreadMutexGetspinloops \
scePthreadMutexSetspinloops \
scePthreadMutexGetyieldloops \
scePthreadMutexSetyieldloops \
scePthreadMutexIsowned \
scePthreadSingle \
scePthreadSuspendAll \
scePthreadSuspend \
scePthreadTimedjoin \
sceKernelMlock \
sceKernelMprotect \
sceKernelMsync \
sceKernelMunlock \
sceKernelMunmap \
sceKernelMlockall \
sceKernelMunlockall \
sceKernelSleep \
sceKernelNanosleep \
sceKernelUsleep \
sceKernelClockGetres \
sceKernelClockGettime \
sceKernelGettimeofday \
sceKernelGettimezone \
sceKernelGetProcessTime \
sceKernelSettimeofday \
sceKernelReboot \
sceKernelError \
sceKernelSetProcessName \
sceKernelGetCurrentCpu \
sceKernelRead \
sceKernelWrite \
sceKernelOpen \
sceKernelClose \
sceKernelUnlink \
sceKernelChmod \
sceKernelSync \
sceKernelFsync \
sceKernelFcntl \
sceKernelReadv \
sceKernelWritev \
sceKernelFchmod \
sceKernelRename \
sceKernelFlock \
sceKernelMkdir \
sceKernelRmdir \
sceKernelUtimes \
sceKernelStat \
sceKernelFstat \
sceKernelFutimes \
sceKernelGetdirentries \
sceKernelGetdents \
sceKernelPreadv \
sceKernelPwritev \
sceKernelPread \
sceKernelPwrite \
sceKernelMmap \
sceKernelLseek \
sceKernelTruncate \
sceKernelFtruncate \
sceKernelGetDirectMemorySize \
sceKernelMapFlexibleMemory \
sceKernelReleaseFlexibleMemory \
sceKernelSetPrtAperture \
sceKernelGetPrtAperture \
sceKernelAllocateDirectMemory \
sceKernelReleaseDirectMemory \
sceKernelMapDirectMemory \
sceKernelGetDirectMemoryType \
sceKernelJitCreateSharedMemory \
sceKernelJitCreateAliasOfSharedMemory \
sceKernelJitMapSharedMemory \
sceKernelJitGetSharedMemoryInfo \
sceKernelQueryMemoryProtection \
sceKernelIsStack \
sceKernelBatchMap \
sceKernelSetVmContainer \
sceKernelVirtualQuery \
sceKernelClearGameDirectMemory \
sceKernelSetVirtualRangeName \
sceKernelMapNamedFlexibleMemory \
sceKernelMapNamedDirectMemory \
sceKernelReserveVirtualRange \
sceKernelSendNotificationRequest \
sceKernelGetTscFrequency \
sceKernelReadTsc \
sceKernelCreateEventFlag \
sceKernelDeleteEventFlag \
sceKernelWaitEventFlag \
sceKernelPollEventFlag \
sceKernelSetEventFlag \
sceKernelClearEventFlag \
sceKernelCancelEventFlag \
sceKernelOpenEventFlag \
sceKernelCloseEventFlag \
sceKernelCreateSema \
sceKernelDeleteSema \
sceKernelWaitSema \
sceKernelPollSema \
sceKernelSignalSema \
sceKernelCancelSema \
sceKernelOpenSema \
sceKernelCloseSema \
sceKernelLoadStartModule \
sceKernelStopUnloadModule \
sceKernelDlsym \
sceKernelGetModuleList \
sceKernelGetModuleInfo \
sceKernelGetModuleInfoFromAddr \
dlopen \
dlclose \
dlerror \
dlsym \
sceKernelGetProcParam \
sceKernelGetSystemSwVersion \
sceKernelGetCompiledSdkVersion \
sceKernelSpawn \
sceKernelGetEventId \
sceKernelGetEventData \
sceKernelGetEventFflags \
sceKernelGetEventError \
sceKernelGetEventUserData \
sceKernelCreateEqueue \
sceKernelDeleteEqueue \
sceKernelWaitEqueue \
sceKernelAddTimerEvent \
sceKernelDeleteTimerEvent \
sceKernelAddReadEvent \
sceKernelDeleteReadEvent \
sceKernelAddWriteEvent \
sceKernelDeleteWriteEvent \
sceKernelAddFileEvent \
sceKernelDeleteFileEvent \
sceKernelAddUserEvent \
sceKernelDeleteUserEvent \
sceKernelTriggerUserEvent \
sceKernelIsDevKit \
sceKernelIsTestKit \
sceKernelIsCEX \
sysKernelGetManufacturingMode \
sceKernelGetIdPs \
sceKernelGetOpenPsIdForSystem \
sceKernelGetOpenPsId \
sceKernelCreateBudget \
sceKernelDeleteBudget \
sceKernelGetResourceLimit \
sceKernelGetBudget \
sceKernelSetSafemode \
sceKernelIccSetBuzzer \
sceKernelIccGetPowerUpCause \
sceKernelIccReadPowerBootMessage \
sceKernelIccGetThermalAlert \
sceKernelUuidCreate \
getargc \
getargv
