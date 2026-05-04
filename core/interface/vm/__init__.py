from .instance import VMInstance
from .state import VMState
from core.interface.arch_config import get_arch_config

class VM(VMInstance, VMState):
    def __init__(self, linux, port, image, hash_tag, arch='amd64', proj_path='/tmp/', mem="2G", cpu="2", key=None, gdb_port=None, mon_port=None, opts=None, log_name='vm.log', log_suffix="", timeout=None, debug=False, logger=None):
        VMInstance.__init__(self, proj_path=proj_path, log_name=log_name, log_suffix=log_suffix, logger=logger, hash_tag=hash_tag, debug=debug, arch=arch)
        self.setup(port=port, image=image, linux=linux, mem=mem, cpu=cpu, key=key, gdb_port=gdb_port, mon_port=mon_port, opts=opts, timeout=timeout)
        arch_config = get_arch_config(arch)
        if gdb_port != None and arch_config["need_gdb"]:
            VMState.__init__(self, linux, gdb_port, arch, proj_path=proj_path, log_suffix=log_suffix, debug=debug)
        else:
            self.gdb = None
            self.mon = None
            self.kernel = None

    def kill(self):
        self.kill_vm()
        if self.gdb != None:
            self.gdb.close()
        if self.mon != None:
            self.mon.close()
        if self.kernel != None and hasattr(self.kernel, 'proj') and self.kernel.proj != None:
            del self.kernel.proj
