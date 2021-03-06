systemcalls := \
cpuset \
cpuset_setid \
cpuset_getid \
cpuset_getaffinity \
cpuset_setaffinity \
getcontext \
setcontext \
swapcontext \
getdtablesize \
dup2 \
dup \
fcntl \
close \
socketclose \
fstat \
fpathconf \
flock \
rdup \
kenv \
kqueue \
kqueueex \
kevent \
execve \
__mac_execve \
exit \
wait4 \
fork \
pdfork \
vfork \
rfork \
ktrace \
utrace \
kldload \
kldunload \
kldunloadf \
kldfind \
kldnext \
kldstat \
kldfirstmod \
kldsym \
adjtime \
getpid \
getppid \
getpgrp \
getpgid \
getsid \
getuid \
geteuid \
getgid \
getegid \
getgroups \
setsid \
setpgid \
setuid \
seteuid \
setgid \
setegid \
setgroups \
setreuid \
setregid \
setresuid \
setresgid \
getresuid \
getresgid \
issetugid \
__setugid \
getlogin \
setlogin \
rctl_get_racct \
rctl_get_rules \
rctl_get_limits \
rctl_add_rule \
rctl_remove_rule \
getpriority \
setpriority \
rtprio_thread \
rtprio \
setrlimit \
getrlimit \
getrusage \
reboot \
sigaction \
sigprocmask \
sigwait \
sigtimedwait \
sigwaitinfo \
sigpending \
sigsuspend \
sigaltstack \
kill \
pdkill \
sigqueue \
yield \
__sysctl \
thr_create \
thr_new \
thr_self \
thr_exit \
thr_kill \
thr_kill2 \
thr_suspend \
thr_wake \
thr_set_name \
clock_gettime \
clock_settime \
clock_getres \
nanosleep \
gettimeofday \
settimeofday \
getitimer \
setitimer \
ktimer_create \
ktimer_delete \
ktimer_settime \
ktimer_gettime \
ktimer_getoverrun \
_umtx_lock \
_umtx_unlock \
_umtx_op \
uuidgen \
sched_setparam \
sched_getparam \
sched_setscheduler \
sched_getscheduler \
sched_yield \
sched_get_priority_max \
sched_get_priority_min \
sched_rr_get_interval \
profil \
cap_enter \
cap_getmode \
cap_new \
cap_getrights \
read \
pread \
readv \
preadv \
write \
pwrite \
writev \
pwritev \
ftruncate \
ioctl \
pselect \
select \
poll \
pipe \
pdgetpid \
ptrace \
sandbox_path \
randomized_path \
workaround8849 \
is_development_mode \
get_paging_stats_of_all_threads \
ksem_init \
ksem_open \
ksem_unlink \
ksem_close \
ksem_post \
ksem_wait \
ksem_timedwait \
ksem_trywait \
ksem_getvalue \
ksem_destroy \
shm_open \
shm_unlink \
socket \
socketex \
netcontrol \
netabort \
netgetsockinfo \
netgetiflist \
bind \
listen \
accept \
connect \
socketpair \
sendto \
sendmsg \
recvfrom \
recvmsg \
shutdown \
setsockopt \
getsockopt \
getsockname \
getpeername \
sendfile \
aio_return \
aio_suspend \
aio_cancel \
aio_error \
aio_read \
aio_write \
aio_waitcomplete \
aio_fsync \
__getcwd \
nmount \
mount \
unmount \
sync \
statfs \
fstatfs \
getfsstat \
fchdir \
chdir \
chroot \
open \
openat \
mknod \
mknodat \
mkfifo \
mkfifoat \
link \
linkat \
symlink \
symlinkat \
unlink \
unlinkat \
lseek \
access \
stat \
fstatat \
lstat \
pathconf \
readlink \
chflags \
lchflags \
fchflags \
chmod \
fchmodat \
lchmod \
fchmod \
chown \
fchownat \
lchown \
fchown \
utimes \
futimesat \
lutimes \
futimes \
truncate \
fsync \
rename \
renameat \
mkdir \
mkdirat \
rmdir \
getdirentries \
getdents \
umask \
revoke \
is_in_sandbox \
__mac_get_pid \
__mac_get_proc \
__mac_set_proc \
__mac_get_fd \
__mac_get_file \
__mac_get_link \
__mac_set_fd \
__mac_set_file \
__mac_set_link \
mac_syscall \
swapon \
sbrk \
sstk \
mmap \
msync \
munmap \
mprotect \
minherit \
madvise \
mincore \
mlock \
mlockall \
munlockall \
munlock \
query_memory_protection \
virtual_query \
batch_map \
set_vm_container \
mname \
get_self_auth_info \
mdbg_call \
mdbg_service \
dynlib_load_prx \
dynlib_unload_prx \
dynlib_dlsym \
dynlib_get_list \
dynlib_get_info \
dynlib_get_info_ex \
dynlib_do_copy_relocations \
dynlib_dlopen \
dynlib_prepare_dlclose \
dynlib_dlclose \
dynlib_get_proc_param \
dynlib_process_needed_and_relocate \
get_proc_type_info \
debug_init \
dl_get_list \
dl_get_info \
dl_get_metadata \
dl_notify_event \
evf_create \
evf_delete \
evf_wait \
evf_trywait \
evf_set \
evf_clear \
evf_cancel \
evf_open \
evf_close \
osem_create \
osem_delete \
osem_wait \
osem_trywait \
osem_post \
osem_cancel \
osem_open \
osem_close \
namedobj_create \
namedobj_delete \
eport_create \
eport_delete \
eport_trigger \
eport_open \
eport_close \
get_authinfo \
opmc_enable \
opmc_disable \
opmc_set_ctl \
opmc_set_ctr \
opmc_get_ctr \
budget_create \
budget_delete \
budget_get \
budget_set \
budget_getid \
budget_get_ptype \
sblock_create \
sblock_delete \
sblock_enter \
sblock_exit \
sblock_xenter \
sblock_xexit \
sigreturn \
dmem_container \
jitshm_create \
jitshm_alias \
suspend_process \
resume_process \
regmgr_call
