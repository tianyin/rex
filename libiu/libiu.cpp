#define _DEFAULT_SOURCE

#include <bpf/libbpf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include "libiu.h"
#include "bindings.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

namespace { // begin anynomous namespace

static const struct bpf_sec_def *find_sec_def(const char *sec_name) {
  int i, n = ARRAY_SIZE(section_defs);

  for (i = 0; i < n; i++) {
    if (strncmp(sec_name, section_defs[i].sec, section_defs[i].len))
      continue;
    return &section_defs[i];
  }
  return NULL;
}

class iu_obj; // forward declaration

static int debug = 0;
static std::unordered_map<int, std::unique_ptr<iu_obj>> objs;

static inline int64_t get_file_size(int fd) {
  struct stat st;
  if (fstat(fd, &st) < 0) {
    perror("fstat");
    return -1;
  }

  return st.st_size;
}

template <typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline T val_from_buf(const unsigned char *buf) {
  return *reinterpret_cast<const T *>(buf);
}

template <typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline void val_to_buf(unsigned char *buf, const T val) {
  *reinterpret_cast<T *>(buf) = val;
}

static inline long bpf(__u64 cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(__NR_bpf, cmd, attr, size);
}

// This struct is POD, meaning the C++ standard guarantees the same memory
// layout as that of the equivalent C struct
// https://stackoverflow.com/questions/422830/structure-of-a-c-object-in-memory-vs-a-struct
struct map_def {
  uint32_t map_type;
  uint32_t key_size;
  uint32_t val_size;
  uint32_t max_size;
  uint32_t map_flag;
  void *kptr;
};

class iu_map {
  map_def def;
  int map_fd;
  const std::string name; // for debug msg

public:
  iu_map() = delete;
  iu_map(const Elf_Data *, Elf64_Addr, Elf64_Off, const char *);
  ~iu_map();

  int create();

  friend class iu_obj; // for debug msg
};

iu_map::iu_map(const Elf_Data *data, Elf64_Addr base, Elf64_Off off,
               const char *c_name)
    : map_fd(-1), name(c_name) {
  auto def_addr = reinterpret_cast<uint64_t>(data->d_buf) + off - base;
  this->def = *reinterpret_cast<map_def *>(def_addr);

  if (debug) {
    std::clog << "sym_name=" << c_name << std::endl;
    std::clog << "map_type=" << this->def.map_type << std::endl;
    std::clog << "key_size=" << this->def.key_size << std::endl;
    std::clog << "val_size=" << this->def.val_size << std::endl;
    std::clog << "max_size=" << this->def.max_size << std::endl;
    std::clog << "map_flag=" << this->def.map_flag << std::endl;
  }
}

iu_map::~iu_map() {
  if (map_fd >= 0)
    close(map_fd);
}

int iu_map::create() {
  const auto &def = this->def;

  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));

  attr.map_type = def.map_type;
  attr.key_size = def.key_size;
  attr.value_size = def.val_size;
  attr.max_entries = def.max_size;
  attr.map_flags = def.map_flag;

  if (name.size() < BPF_OBJ_NAME_LEN)
    memcpy(attr.map_name, name.c_str(), name.size());

  this->map_fd = static_cast<int>(bpf(BPF_MAP_CREATE, &attr, sizeof(attr)));
  return this->map_fd;
}

class iu_obj {
  struct iu_prog {
    std::string name;
    int prog_type;
    Elf64_Off offset;
    int fd;

    iu_prog() = delete;
    iu_prog(const char *nm, int prog_ty, Elf64_Off off)
        : name(nm), prog_type(prog_ty), offset(off), fd(-1) {}
    ~iu_prog() = default;
  };

  std::unordered_map<Elf64_Off, iu_map> map_defs;
  std::unordered_map<std::string, const iu_map *> name2map;
  std::unordered_map<std::string, iu_prog> progs;

  Elf *elf;
  Elf_Scn *symtab_scn;
  Elf_Scn *dynsym_scn;
  Elf_Scn *maps_scn;

  // Global Offset Table for PIE
  Elf_Scn *got_scn;

  // Dynamic relocation for PIE
  Elf_Scn *rela_dyn_scn;
  std::vector<iu_rela_dyn> dyn_relas;
  std::vector<iu_dyn_sym> dyn_syms;

  size_t file_size;
  unsigned char *file_map;
  int prog_fd;
  std::string basename;

  int parse_scns();
  int parse_maps();
  int parse_progs();
  int parse_got();
  int parse_rela_dyn();

public:
  iu_obj() = delete;
  explicit iu_obj(const char *);
  iu_obj(const iu_obj &) = delete;
  iu_obj(iu_obj &&) = delete;
  ~iu_obj();

  iu_obj &operator=(const iu_obj &) = delete;
  iu_obj &operator=(iu_obj &&) = delete;

  // Making this a separate function to avoid exceptions in constructor
  int parse_elf();

  int fix_maps();
  int load();
  int find_map_by_name(const char *) const;
  int find_prog_by_name(const char *) const;
};

} // namespace

iu_obj::iu_obj(const char *c_path)
    : map_defs(), symtab_scn(nullptr), dynsym_scn(nullptr), maps_scn(nullptr),
      prog_fd(-1) {
  int fd = open(c_path, 0, O_RDONLY);
  this->elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
  file_size = get_file_size(fd);

  // MAP_PRIVATE ensures the changes are not carried through to the backing
  // file
  // reference: `man 2 mmap`
  file_map = reinterpret_cast<unsigned char *>(
      mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0));

  std::string copy(c_path);
  copy += ".base";
  basename = ::basename(copy.data());
  close(fd);
}

iu_obj::~iu_obj() {
  if (this->elf)
    elf_end(this->elf);

  if (file_map)
    munmap(file_map, file_size);

  if (prog_fd >= 0)
    close(prog_fd);
}

int iu_obj::parse_scns() {
  size_t shstrndx;

  if (elf_getshdrstrndx(elf, &shstrndx)) {
    std::cerr << "elf: failed to get section names section index for "
              << std::endl;
    return -1;
  }

  for (auto scn = elf_nextscn(elf, NULL); scn; scn = elf_nextscn(elf, scn)) {
    char *name;
    int idx = elf_ndxscn(scn);
    Elf64_Shdr *sh = elf64_getshdr(scn);
    if (!sh) {
      std::cerr << "elf: failed to get section header, idx=" << idx
                << std::endl;
      return -1;
    }

    name = elf_strptr(this->elf, shstrndx, sh->sh_name);

    if (!name) {
      std::cerr << "elf: failed to get section name" << std::endl;
      return -1;
    }

    if (debug)
      std::clog << "section " << name << ", idx=" << idx << std::endl;

    if (sh->sh_type == SHT_SYMTAB && !strcmp(".symtab", name))
      this->symtab_scn = scn;
    else if (sh->sh_type == SHT_DYNSYM && !strcmp(".dynsym", name))
      this->dynsym_scn = scn;
    else if (!strcmp(".maps", name))
      this->maps_scn = scn;
    else if (sh->sh_type == SHT_RELA && !strcmp(".rela.dyn", name))
      this->rela_dyn_scn = scn;
  }

  if (!this->maps_scn && debug)
    std::clog << "section .maps not found" << std::endl;

  if (!this->rela_dyn_scn && debug)
    std::clog << "section .rela.dyn not found" << std::endl;

  return 0;
}

int iu_obj::parse_maps() {
  Elf_Data *maps, *syms;
  int nr_syms, nr_maps = 0, maps_shndx;
  size_t strtabidx;
  Elf64_Addr maps_shaddr;

  if (!this->maps_scn)
    return 0;

  maps = elf_getdata(maps_scn, 0);
  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }

  if (!maps) {
    std::cerr << "elf: failed to get map definitions" << std::endl;
    return -1;
  }

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;
  maps_shndx = elf_ndxscn(maps_scn);
  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    char *name;

    if (sym->st_shndx != maps_shndx ||
        ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
      continue;

    name = elf_strptr(elf, strtabidx, sym->st_name);
    if (debug) {
      std::clog << "symbol: " << name << ", st_value=0x" << std::hex
                << sym->st_value << ", st_size=" << std::dec << sym->st_size
                << std::endl;
    }

    if (sym->st_size == sizeof(struct map_def)) {
      map_defs.try_emplace(sym->st_value, maps, maps_shaddr, sym->st_value,
                           name);
    }

    nr_maps++;
  }

  if (debug)
    std::clog << "# of symbols in \".maps\": " << nr_maps << std::endl;

  return 0;
}

// get sec name
// get function symbols
int iu_obj::parse_progs() {
  size_t shstrndx, strtabidx;
  Elf_Data *syms;
  int nr_syms;

  strtabidx = elf64_getshdr(symtab_scn)->sh_link;

  if (elf_getshdrstrndx(elf, &shstrndx)) {
    std::cerr << "elf: failed to get section names section index" << std::endl;
    return -1;
  }

  syms = elf_getdata(symtab_scn, 0);

  if (!syms) {
    std::cerr << "elf: failed to get symbol definitions" << std::endl;
    return -1;
  }

  nr_syms = syms->d_size / sizeof(Elf64_Sym);

  for (int i = 0; i < nr_syms; i++) {
    Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + i;
    Elf_Scn *scn = elf_getscn(this->elf, sym->st_shndx);
    char *scn_name, *sym_name;
    const struct bpf_sec_def *sec_def;

    if (!scn || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    scn_name = elf_strptr(this->elf, shstrndx, elf64_getshdr(scn)->sh_name);
    sym_name = elf_strptr(elf, strtabidx, sym->st_name);
    /*if (debug) {
            std::clog << "section: \"" << scn_name << "\"" << std::endl;
            std::clog << "symbol: \"" << sym_name << "\"" << std::endl;
    }*/

    sec_def = find_sec_def(scn_name);
    if (!sec_def)
      continue;
    int prog_type = sec_def->prog_type;

    sym_name = elf_strptr(elf, strtabidx, sym->st_name);
    progs.try_emplace(sym_name, sym_name, prog_type, sym->st_value);

  }
  return 0;
};

int iu_obj::parse_rela_dyn() {
  int ret;
  Elf64_Shdr *rela_dyn;
  iu_rela_dyn *rela_dyn_data;
  uint64_t rela_dyn_addr, rela_dyn_size, nr_dyn_relas;
  int idx;

  if (!this->rela_dyn_scn)
    return 0;

  rela_dyn = elf64_getshdr(rela_dyn_scn);

  if (!rela_dyn) {
    std::cerr << "elf: failed to get .rela.dyn section" << std::endl;
    return -1;
  }

  rela_dyn_data =
      reinterpret_cast<iu_rela_dyn *>(elf_getdata(rela_dyn_scn, 0)->d_buf);
  rela_dyn_addr = rela_dyn->sh_addr;
  rela_dyn_size = rela_dyn->sh_size;

  if (debug) {
    std::clog << ".rela.dyn offset=" << std::hex << rela_dyn_addr
              << ", .rela.dyn size=" << std::dec << rela_dyn_size << std::endl;
  }

  if (rela_dyn_size % sizeof(iu_rela_dyn)) {
    std::cerr << "elf: ill-formed .rela.dyn section" << std::endl;
    return -1;
  }

  nr_dyn_relas = rela_dyn_size / sizeof(iu_rela_dyn);

  for (idx = 0; idx < nr_dyn_relas; idx++) {
    // Need to skip the map relocs, these are handled differently in the kernel
    if (map_defs.find(rela_dyn_data[idx].addend) != map_defs.end())
      continue;

    if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_RELATIVE) {
      dyn_relas.push_back(rela_dyn_data[idx]);
    } else if (ELF64_R_TYPE(rela_dyn_data[idx].info) == R_X86_64_GLOB_DAT) {
      uint32_t dynsym_idx = ELF64_R_SYM(rela_dyn_data[idx].info);
      Elf_Data *syms = elf_getdata(dynsym_scn, 0);
      size_t strtabidx = elf64_getshdr(dynsym_scn)->sh_link;
      Elf64_Sym *sym = reinterpret_cast<Elf64_Sym *>(syms->d_buf) + dynsym_idx;
      iu_dyn_sym dyn_sym = {0};
      char *name = strdup(elf_strptr(elf, strtabidx, sym->st_name));

      if (!name) {
        std::cerr << "failed to alloc symbol name" << std::endl;
        return -1;
      }

      dyn_sym.offset = rela_dyn_data[idx].offset;
      dyn_sym.symbol = reinterpret_cast<__u64>(name);

      dyn_syms.push_back(dyn_sym);
    } else {
      std::cerr << "elf: relocation type not supported" << std::endl;
      return -1;
    }
  }

  if (debug) {
    std::clog << ".rela.dyn: " << std::hex << std::endl;
    for (auto &dyn_rela : dyn_relas) {
      std::clog << "0x" << dyn_rela.offset << ", 0x" << dyn_rela.info << ", 0x"
                << dyn_rela.addend << std::endl;
    }
    for (auto &dyn_sym : dyn_syms) {
      std::clog << "0x" << dyn_sym.offset << ", "
                << reinterpret_cast<char *>(dyn_sym.symbol) << std::endl;
    }
    std::clog << std::dec;
  }

  return 0;
}

int iu_obj::parse_elf() {
  int ret;

  if (!elf) {
    std::cerr << "elf: failed to open object" << std::endl;
    return -1;
  }

  ret = this->parse_scns();
  ret = ret < 0 ?: this->parse_maps();
  ret = ret < 0 ?: this->parse_progs();
  ret = ret < 0 ?: this->parse_rela_dyn();

  return ret;
}

int iu_obj::fix_maps() {
  Elf64_Addr maps_shaddr;
  Elf64_Off maps_shoff;

  if (!this->maps_scn) {
    return 0;
  }

  maps_shaddr = elf64_getshdr(maps_scn)->sh_addr;
  maps_shoff = elf64_getshdr(maps_scn)->sh_offset;

  if (debug) {
    std::clog << ".maps section file offset=0x" << std::hex
              << elf64_getshdr(maps_scn)->sh_offset << std::dec << std::endl;
  }

  if (this->file_size < 0 || reinterpret_cast<int64_t>(this->file_map) < 0) {
    perror("mmap");
    return -1;
  }

  for (auto &def : map_defs) {
    size_t kptr_file_off =
        def.first + offsetof(map_def, kptr) - maps_shaddr + maps_shoff;
    int map_fd;

    if (debug) {
      std::clog << "map_ptr=0x" << std::hex << def.first << std::dec
                << std::endl;
      std::clog << "map_name=\"" << def.second.name << '\"' << std::endl;
    }

    map_fd = def.second.create();
    if (map_fd < 0) {
      perror("bpf_map_create");
      return -1;
    }

    name2map.insert(std::make_pair(def.second.name, &def.second));

    if (debug)
      std::clog << "map_fd=" << map_fd << std::endl;

    val_to_buf<uint64_t>(&this->file_map[kptr_file_off], map_fd);
  }

  return 0;
}

int iu_obj::load() {
  int fd;
  auto arr = std::make_unique<uint64_t[]>(map_defs.size());
  union bpf_attr attr = {0};
  int idx = 0, ret = 0;

  // TODO: Will have race condition if multiple objs loaded at same time
  std::ofstream output("rust.out", std::ios::out | std::ios::binary);

  output.write((char *)this->file_map, this->file_size);
  output.close();

  fd = open("rust.out", O_RDONLY);

  for (auto &def : map_defs)
    arr[idx++] = def.first + offsetof(map_def, kptr);

  attr.prog_type = BPF_PROG_TYPE_IU_BASE;
  // progname was zero-initialized so we don't copy the null terminator
  memcpy(attr.prog_name, basename.c_str(),
         std::min(basename.size(), sizeof(attr.prog_name) - 1));
  attr.rustfd = fd;
  attr.license = reinterpret_cast<__u64>("GPL");

  attr.map_offs = reinterpret_cast<__u64>(arr.get());
  attr.map_cnt = map_defs.size();

  attr.dyn_relas = reinterpret_cast<__u64>(dyn_relas.data());
  attr.nr_dyn_relas = dyn_relas.size();

  attr.dyn_syms = reinterpret_cast<__u64>(dyn_syms.data());
  attr.nr_dyn_syms = dyn_syms.size();

  ret = bpf(BPF_PROG_LOAD_IU_BASE, &attr, sizeof(attr));

  if (ret < 0) {
    perror("bpf_prog_load_iu_base");
    return -1;
  }

  this->prog_fd = ret;

  if (debug)
    std::clog << "Base program loaded, fd = " << ret << std::endl;

  if (remove("rust.out") < 0) {
    perror("remove");
    goto close_fds;
  }

  for (auto &it : progs) {
    attr.prog_type = it.second.prog_type;
    strncpy(attr.prog_name, it.second.name.c_str(), sizeof(attr.prog_name) - 1);
    attr.base_prog_fd = this->prog_fd;
    attr.prog_offset = it.second.offset;
    attr.license = (__u64) "GPL";
    it.second.fd = bpf(BPF_PROG_LOAD_IU, &attr, sizeof(attr));

    if (it.second.fd < 0) {
      perror("bpf_prog_load_iu");
      goto close_fds;
    }

    if (debug)
      std::clog << "Program " << it.first << " loaded, fd = " << it.second.fd
                << std::endl;
  }
  return ret;

close_fds:
  for (auto &it : progs) {
    if (it.second.fd >= 0)
      close(it.second.fd);
  }
  close(this->prog_fd);
  return -1;
}

int iu_obj::find_map_by_name(const char *name) const {
  auto it = name2map.find(name);
  return it != name2map.end() ? it->second->map_fd : -1;
}

int iu_obj::find_prog_by_name(const char *name) const {
  auto it = progs.find(name);
  return it != progs.end() ? it->second.fd : -1;
}

void iu_set_debug(const int val) { debug = val; }

int iu_obj_load(const char *file_path) {
  int ret;

  if (elf_version(EV_CURRENT) == EV_NONE) {
    std::cerr << "elf: failed to init libelf" << std::endl;
    return -1;
  }

  auto obj = std::make_unique<iu_obj>(file_path);

  ret = obj->parse_elf();
  ret = ret ?: obj->fix_maps();
  ret = ret ?: obj->load();

  if (ret >= 0)
    objs[ret] = std::move(obj);

  return ret;
}

int iu_obj_close(int prog_fd) {
  auto it = objs.find(prog_fd);
  if (it != objs.end()) {
    objs.erase(it);
    return 0;
  }

  return -1;
}

int iu_obj_get_map(int prog_fd, const char *map_name) {
  auto it = objs.find(prog_fd);
  return it != objs.end() ? it->second->find_map_by_name(map_name) : -1;
}

int iu_obj_get_prog(int prog_fd, const char *prog_name) {
  auto it = objs.find(prog_fd);
  return it != objs.end() ? it->second->find_prog_by_name(prog_name) : -1;
}

