#define _KERNEL

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/param.h>

#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/ucred.h>

#include <machine/specialreg.h>
#include <machine/cpufunc.h>

#include <ps4/kernel.h>

void ps4KernelPrivilegeRoot()
{
	struct thread *td;
	struct ucred *cr;

	ps4KernelThreadGetCurrent(&td);
	cr = td->td_proc->p_ucred;
	cr->cr_uid = cr->cr_ruid = cr->cr_rgid = 0;
	//cr->cr_groups[0] = 0;
}

int ps4KernelPrivilegeUnjail()
{
	struct thread *td;
	struct filedesc	*fd;
	struct ucred *cr;
	void *t;

	ps4KernelThreadGetCurrent(&td);



	ps4ExpressionReturnOnError(ps4KernelSymbolLookUp("prison0", &t));
	cr = td->td_proc->p_ucred;
	cr->cr_prison = (struct prison *)t;

	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process
	
	((uint64_t *)0xFFFFFFFF832CC2E8)[0] = 0x123456; //priv_check_cred bypass with suser_enabled=true
	((uint64_t *)0xFFFFFFFF8323DA18)[0] = 0; // bypass priv_check

	ps4ExpressionReturnOnError(ps4KernelSymbolLookUp("rootvnode", &t));
	fd = td->td_proc->p_fd;
	//fd->fd_cdir =
	fd->fd_rdir = fd->fd_jdir = *(struct vnode **)t;

	return PS4_OK;
}


int ps4KernelPrivilegeEscalate()
{
	ps4KernelPrivilegeRoot();
	ps4ExpressionReturnOnError(ps4KernelPrivilegeUnjail());
	return PS4_OK;
}
