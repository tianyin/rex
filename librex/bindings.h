// This file contains the non-portable part, it has to mirror some libbpf types
// for now

#ifndef _LIBREX_BINDINGS_H
#define _LIBREX_BINDINGS_H

#include <gelf.h>

struct list_head {
  struct list_head *prev, *next;
};

struct bpf_sec_def;

typedef struct bpf_link *(*attach_fn_t)(const struct bpf_sec_def *sec,
                                        struct bpf_program *prog);

struct bpf_sec_def {
  const char *sec;
  size_t len;
  enum bpf_prog_type prog_type;
  enum bpf_attach_type expected_attach_type;
  bool is_exp_attach_type_optional;
  bool is_attachable;
  bool is_attach_btf;
  bool is_sleepable;
  attach_fn_t attach_fn;
};

#define BPF_PROG_SEC_IMPL(string, ptype, eatype, eatype_optional, attachable,  \
                          attach_btf)                                          \
  {                                                                            \
    .sec = string, .len = sizeof(string) - 1, .prog_type = ptype,              \
    .expected_attach_type = (enum bpf_attach_type)eatype,                      \
    .is_exp_attach_type_optional = eatype_optional,                            \
    .is_attachable = attachable, .is_attach_btf = attach_btf,                  \
  }

/* Programs that can NOT be attached. */
#define BPF_PROG_SEC(string, ptype) BPF_PROG_SEC_IMPL(string, ptype, 0, 0, 0, 0)

/* Programs that can be attached. */
#define BPF_APROG_SEC(string, ptype, atype)                                    \
  BPF_PROG_SEC_IMPL(string, ptype, atype, true, 1, 0)

/* Programs that must specify expected attach type at load time. */
#define BPF_EAPROG_SEC(string, ptype, eatype)                                  \
  BPF_PROG_SEC_IMPL(string, ptype, eatype, false, 1, 0)

/* Programs that use BTF to identify attach point */
#define BPF_PROG_BTF(string, ptype, eatype)                                    \
  BPF_PROG_SEC_IMPL(string, ptype, eatype, false, 0, 1)

/* Programs that can be attached but attach type can't be identified by section
 * name. Kept for backward compatibility.
 */
#define BPF_APROG_COMPAT(string, ptype) BPF_PROG_SEC(string, ptype)

#define SEC_DEF(sec_pfx, ptype, ...)                                           \
  {                                                                            \
    .sec = sec_pfx, .len = sizeof(sec_pfx) - 1,                                \
    .prog_type = BPF_PROG_TYPE_##ptype, __VA_ARGS__                            \
  }

extern "C" {
extern struct bpf_link *attach_kprobe(const struct bpf_sec_def *sec,
                                      struct bpf_program *prog);
extern struct bpf_link *attach_tp(const struct bpf_sec_def *sec,
                                  struct bpf_program *prog);
extern struct bpf_link *attach_raw_tp(const struct bpf_sec_def *sec,
                                      struct bpf_program *prog);
extern struct bpf_link *attach_trace(const struct bpf_sec_def *sec,
                                     struct bpf_program *prog);
extern struct bpf_link *attach_lsm(const struct bpf_sec_def *sec,
                                   struct bpf_program *prog);
extern struct bpf_link *attach_iter(const struct bpf_sec_def *sec,
                                    struct bpf_program *prog);
}

static const struct bpf_sec_def section_defs[] = {
    BPF_PROG_SEC("socket", BPF_PROG_TYPE_SOCKET_FILTER),
    BPF_EAPROG_SEC("sk_reuseport/migrate", BPF_PROG_TYPE_SK_REUSEPORT,
                   BPF_SK_REUSEPORT_SELECT_OR_MIGRATE),
    BPF_EAPROG_SEC("sk_reuseport", BPF_PROG_TYPE_SK_REUSEPORT,
                   BPF_SK_REUSEPORT_SELECT),
    SEC_DEF("kprobe/", KPROBE, .attach_fn = attach_kprobe),
    BPF_PROG_SEC("uprobe/", BPF_PROG_TYPE_KPROBE),
    SEC_DEF("kretprobe/", KPROBE, .attach_fn = attach_kprobe),
    BPF_PROG_SEC("uretprobe/", BPF_PROG_TYPE_KPROBE),
    BPF_PROG_SEC("tc", BPF_PROG_TYPE_SCHED_CLS),
    BPF_PROG_SEC("classifier", BPF_PROG_TYPE_SCHED_CLS),
    BPF_PROG_SEC("action", BPF_PROG_TYPE_SCHED_ACT),
    SEC_DEF("tracepoint/", TRACEPOINT, .attach_fn = attach_tp),
    SEC_DEF("tp/", TRACEPOINT, .attach_fn = attach_tp),
    SEC_DEF("raw_tracepoint/", RAW_TRACEPOINT, .attach_fn = attach_raw_tp),
    SEC_DEF("raw_tp/", RAW_TRACEPOINT, .attach_fn = attach_raw_tp),
    SEC_DEF("tp_btf/", TRACING, .expected_attach_type = BPF_TRACE_RAW_TP,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fentry/", TRACING, .expected_attach_type = BPF_TRACE_FENTRY,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fmod_ret/", TRACING, .expected_attach_type = BPF_MODIFY_RETURN,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fexit/", TRACING, .expected_attach_type = BPF_TRACE_FEXIT,
            .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("fentry.s/", TRACING, .expected_attach_type = BPF_TRACE_FENTRY,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("fmod_ret.s/", TRACING, .expected_attach_type = BPF_MODIFY_RETURN,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("fexit.s/", TRACING, .expected_attach_type = BPF_TRACE_FEXIT,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_trace),
    SEC_DEF("freplace/", EXT, .is_attach_btf = true, .attach_fn = attach_trace),
    SEC_DEF("lsm/", LSM, .expected_attach_type = BPF_LSM_MAC,
            .is_attach_btf = true, .attach_fn = attach_lsm),
    SEC_DEF("lsm.s/", LSM, .expected_attach_type = BPF_LSM_MAC,
            .is_attach_btf = true, .is_sleepable = true,
            .attach_fn = attach_lsm),
    SEC_DEF("iter/", TRACING, .expected_attach_type = BPF_TRACE_ITER,
            .is_attach_btf = true, .attach_fn = attach_iter),
    SEC_DEF("syscall", SYSCALL, .is_sleepable = true),
    BPF_EAPROG_SEC("xdp_devmap/", BPF_PROG_TYPE_XDP, BPF_XDP_DEVMAP),
    BPF_EAPROG_SEC("xdp_cpumap/", BPF_PROG_TYPE_XDP, BPF_XDP_CPUMAP),
    BPF_APROG_SEC("xdp", BPF_PROG_TYPE_XDP, BPF_XDP),
    BPF_PROG_SEC("perf_event", BPF_PROG_TYPE_PERF_EVENT),
    BPF_PROG_SEC("lwt_in", BPF_PROG_TYPE_LWT_IN),
    BPF_PROG_SEC("lwt_out", BPF_PROG_TYPE_LWT_OUT),
    BPF_PROG_SEC("lwt_xmit", BPF_PROG_TYPE_LWT_XMIT),
    BPF_PROG_SEC("lwt_seg6local", BPF_PROG_TYPE_LWT_SEG6LOCAL),
    BPF_APROG_SEC("cgroup_skb/ingress", BPF_PROG_TYPE_CGROUP_SKB,
                  BPF_CGROUP_INET_INGRESS),
    BPF_APROG_SEC("cgroup_skb/egress", BPF_PROG_TYPE_CGROUP_SKB,
                  BPF_CGROUP_INET_EGRESS),
    BPF_APROG_COMPAT("cgroup/skb", BPF_PROG_TYPE_CGROUP_SKB),
    BPF_EAPROG_SEC("cgroup/sock_create", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET_SOCK_CREATE),
    BPF_EAPROG_SEC("cgroup/sock_release", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET_SOCK_RELEASE),
    BPF_APROG_SEC("cgroup/sock", BPF_PROG_TYPE_CGROUP_SOCK,
                  BPF_CGROUP_INET_SOCK_CREATE),
    BPF_EAPROG_SEC("cgroup/post_bind4", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET4_POST_BIND),
    BPF_EAPROG_SEC("cgroup/post_bind6", BPF_PROG_TYPE_CGROUP_SOCK,
                   BPF_CGROUP_INET6_POST_BIND),
    BPF_APROG_SEC("cgroup/dev", BPF_PROG_TYPE_CGROUP_DEVICE, BPF_CGROUP_DEVICE),
    BPF_APROG_SEC("sockops", BPF_PROG_TYPE_SOCK_OPS, BPF_CGROUP_SOCK_OPS),
    BPF_APROG_SEC("sk_skb/stream_parser", BPF_PROG_TYPE_SK_SKB,
                  BPF_SK_SKB_STREAM_PARSER),
    BPF_APROG_SEC("sk_skb/stream_verdict", BPF_PROG_TYPE_SK_SKB,
                  BPF_SK_SKB_STREAM_VERDICT),
    BPF_APROG_COMPAT("sk_skb", BPF_PROG_TYPE_SK_SKB),
    BPF_APROG_SEC("sk_msg", BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT),
    BPF_APROG_SEC("lirc_mode2", BPF_PROG_TYPE_LIRC_MODE2, BPF_LIRC_MODE2),
    BPF_APROG_SEC("flow_dissector", BPF_PROG_TYPE_FLOW_DISSECTOR,
                  BPF_FLOW_DISSECTOR),
    BPF_EAPROG_SEC("cgroup/bind4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_BIND),
    BPF_EAPROG_SEC("cgroup/bind6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_BIND),
    BPF_EAPROG_SEC("cgroup/connect4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_CONNECT),
    BPF_EAPROG_SEC("cgroup/connect6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_CONNECT),
    BPF_EAPROG_SEC("cgroup/sendmsg4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP4_SENDMSG),
    BPF_EAPROG_SEC("cgroup/sendmsg6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP6_SENDMSG),
    BPF_EAPROG_SEC("cgroup/recvmsg4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP4_RECVMSG),
    BPF_EAPROG_SEC("cgroup/recvmsg6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_UDP6_RECVMSG),
    BPF_EAPROG_SEC("cgroup/getpeername4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_GETPEERNAME),
    BPF_EAPROG_SEC("cgroup/getpeername6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_GETPEERNAME),
    BPF_EAPROG_SEC("cgroup/getsockname4", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET4_GETSOCKNAME),
    BPF_EAPROG_SEC("cgroup/getsockname6", BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                   BPF_CGROUP_INET6_GETSOCKNAME),
    BPF_EAPROG_SEC("cgroup/sysctl", BPF_PROG_TYPE_CGROUP_SYSCTL,
                   BPF_CGROUP_SYSCTL),
    BPF_EAPROG_SEC("cgroup/getsockopt", BPF_PROG_TYPE_CGROUP_SOCKOPT,
                   BPF_CGROUP_GETSOCKOPT),
    BPF_EAPROG_SEC("cgroup/setsockopt", BPF_PROG_TYPE_CGROUP_SOCKOPT,
                   BPF_CGROUP_SETSOCKOPT),
    BPF_PROG_SEC("struct_ops", BPF_PROG_TYPE_STRUCT_OPS),
    BPF_EAPROG_SEC("sk_lookup/", BPF_PROG_TYPE_SK_LOOKUP, BPF_SK_LOOKUP),
};

#undef BPF_PROG_SEC_IMPL
#undef BPF_PROG_SEC
#undef BPF_APROG_SEC
#undef BPF_EAPROG_SEC
#undef BPF_APROG_COMPAT
#undef SEC_DEF

struct bpf_object {
  char name[BPF_OBJ_NAME_LEN];
  char license[64];
  __u32 kern_version;

  struct bpf_program *programs;
  size_t nr_programs;
  struct bpf_map *maps;
  size_t nr_maps;
  size_t maps_cap;

  char *kconfig;
  struct extern_desc *externs;
  int nr_extern;
  int kconfig_map_idx;
  int rodata_map_idx;

  bool loaded;
  bool has_subcalls;

  struct bpf_gen *gen_loader;

  struct {
    int fd;
    const void *obj_buf;
    size_t obj_buf_sz;
    Elf *elf;
    GElf_Ehdr ehdr;
    Elf_Data *symbols;
    Elf_Data *data;
    Elf_Data *rodata;
    Elf_Data *bss;
    Elf_Data *st_ops_data;
    size_t shstrndx; /* section index for section name strings */
    size_t strtabidx;
    struct {
      GElf_Shdr shdr;
      Elf_Data *data;
    } *reloc_sects;
    int nr_reloc_sects;
    int maps_shndx;
    int btf_maps_shndx;
    __u32 btf_maps_sec_btf_id;
    int text_shndx;
    int symbols_shndx;
    int data_shndx;
    int rodata_shndx;
    int bss_shndx;
    int st_ops_shndx;
  } efile;

  struct list_head list;

  struct btf *btf;
  struct btf_ext *btf_ext;

  struct btf *btf_vmlinux;
  char *btf_custom_path;
  struct btf *btf_vmlinux_override;
  struct module_btf *btf_modules;
  bool btf_modules_loaded;
  size_t btf_module_cnt;
  size_t btf_module_cap;

  void *priv;
  bpf_object_clear_priv_t clear_priv;

  char path[];
};

struct bpf_program {
  const struct bpf_sec_def *sec_def;
  char *sec_name;
  size_t sec_idx;
  size_t sec_insn_off;
  size_t sec_insn_cnt;
  size_t sub_insn_off;

  char *name;
  char *pin_name;

  struct bpf_insn *insns;
  size_t insns_cnt;

  struct reloc_desc *reloc_desc;
  int nr_reloc;
  int log_level;

  struct {
    int nr;
    int *fds;
  } instances;
  bpf_program_prep_t preprocessor;

  struct bpf_object *obj;
  void *priv;
  bpf_program_clear_priv_t clear_priv;

  bool load;
  bool mark_btf_static;
  enum bpf_prog_type type;
  enum bpf_attach_type expected_attach_type;
  int prog_ifindex;
  __u32 attach_btf_obj_fd;
  __u32 attach_btf_id;
  __u32 attach_prog_fd;
  void *func_info;
  __u32 func_info_rec_size;
  __u32 func_info_cnt;

  void *line_info;
  __u32 line_info_rec_size;
  __u32 line_info_cnt;
  __u32 prog_flags;
};

enum libbpf_map_type {
  LIBBPF_MAP_UNSPEC,
  LIBBPF_MAP_DATA,
  LIBBPF_MAP_BSS,
  LIBBPF_MAP_RODATA,
  LIBBPF_MAP_KCONFIG,
};

struct bpf_map {
  char *name;
  int fd;
  int sec_idx;
  size_t sec_offset;
  int map_ifindex;
  int inner_map_fd;
  struct bpf_map_def def;
  __u32 numa_node;
  __u32 btf_var_idx;
  __u32 btf_key_type_id;
  __u32 btf_value_type_id;
  __u32 btf_vmlinux_value_type_id;
  void *priv;
  bpf_map_clear_priv_t clear_priv;
  enum libbpf_map_type libbpf_type;
  void *mmaped;
  struct bpf_struct_ops *st_ops;
  struct bpf_map *inner_map;
  void **init_slots;
  int init_slots_sz;
  char *pin_path;
  bool pinned;
  bool reused;
};

#endif // _LIBREX_BINDINGS_H
