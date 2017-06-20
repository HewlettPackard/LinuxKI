#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x806e575f, "kmem_cache_destroy" },
	{ 0xab57e311, "tracepoint_probe_register" },
	{ 0x4f1939c7, "per_cpu__current_task" },
	{ 0x5a34a45c, "__kmalloc" },
	{ 0x3eba92, "debugfs_create_dir" },
	{ 0x954e8e2, "per_cpu__kstat" },
	{ 0x6307fc98, "del_timer" },
	{ 0x950ffff2, "cpu_online_mask" },
	{ 0xdd822018, "boot_cpu_data" },
	{ 0x52760ca9, "getnstimeofday" },
	{ 0x731433ee, "unregister_timer_hook" },
	{ 0xac72743f, "kallsyms_on_each_symbol" },
	{ 0xc87c1f84, "ktime_get" },
	{ 0x6a9f26c9, "init_timer_key" },
	{ 0xe67d81ba, "strlen_user" },
	{ 0x3758301, "mutex_unlock" },
	{ 0x999e8297, "vfree" },
	{ 0xced11b05, "debugfs_create_file" },
	{ 0x1b9aca3f, "jprobe_return" },
	{ 0x3c2c5af5, "sprintf" },
	{ 0xf0909ad6, "debugfs_remove_recursive" },
	{ 0xb94db510, "register_jprobe" },
	{ 0x1932bfb8, "nonseekable_open" },
	{ 0x7d11c268, "jiffies" },
	{ 0xe2d5255a, "strcmp" },
	{ 0x9629486a, "per_cpu__cpu_number" },
	{ 0xfe7c4287, "nr_cpu_ids" },
	{ 0xde0bdcff, "memset" },
	{ 0xea147363, "printk" },
	{ 0x7ec9bfbc, "strncpy" },
	{ 0x85f8a266, "copy_to_user" },
	{ 0xb4390f9a, "mcount" },
	{ 0xcc3f176f, "per_cpu__x86_cpu_to_node_map" },
	{ 0x7329e40d, "kmem_cache_free" },
	{ 0x3dd5d829, "add_timer_on" },
	{ 0x6dcaeb88, "per_cpu__kernel_stack" },
	{ 0xfee8a795, "mutex_lock" },
	{ 0xc2cdbf1, "synchronize_sched" },
	{ 0x45450063, "mod_timer" },
	{ 0x8b6c553c, "fput" },
	{ 0x57adf756, "per_cpu__this_cpu_off" },
	{ 0xee065ced, "kmem_cache_alloc" },
	{ 0x78764f4e, "pv_irq_ops" },
	{ 0x3a3f86d, "unregister_jprobe" },
	{ 0xf0fdf6cb, "__stack_chk_fail" },
	{ 0x1000e51, "schedule" },
	{ 0xd62c833f, "schedule_timeout" },
	{ 0x80d5cff0, "per_cpu__irq_regs" },
	{ 0x86c7146d, "vfs_fstat" },
	{ 0x266c7c38, "wake_up_process" },
	{ 0xb62d2c5, "print_context_stack_bp" },
	{ 0x32047ad5, "__per_cpu_offset" },
	{ 0xe4a639f8, "kmem_cache_create" },
	{ 0x37a0cba, "kfree" },
	{ 0x236c8c64, "memcpy" },
	{ 0xdc1f8f2e, "register_timer_hook" },
	{ 0xe8116e08, "__kmalloc_node" },
	{ 0x9e0c711d, "vzalloc_node" },
	{ 0x1d95d270, "dump_trace" },
	{ 0xc33f6f4c, "on_each_cpu" },
	{ 0x3302b500, "copy_from_user" },
	{ 0xc4b33aa6, "tracepoint_probe_unregister" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "EF3A078245CC22575F5B1CB");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 6,
};
