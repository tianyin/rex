#include <array>
#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/unistd.h>

#include <libelf.h>

#include "libiu.h"

namespace { // begin anynomous namespace
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

// https://elixir.bootlin.com/linux/v5.15/source/tools/lib/bpf/libbpf.c#L224
struct iu_sec_def {
	const char *sec;
	size_t len;
	bpf_prog_type prog_type;
};

#define SEC_DEF(sec_pfx, ptype) {					    \
	.sec = sec_pfx,							    \
	.len = sizeof(sec_pfx) - 1,					    \
	.prog_type = BPF_PROG_TYPE_##ptype,				    \
}

static iu_sec_def section_defs[] = {
	SEC_DEF("kprobe/", KPROBE),
	SEC_DEF("tracepoint/", TRACEPOINT),
	// more sec defs in the future
};

#undef SEC_DEF

static int find_sec_def(const char *sec_name)
{
	int i, n = ARRAY_SIZE(section_defs);

	for (i = 0; i < n; i++) {
		if (strncmp(sec_name,
			    section_defs[i].sec, section_defs[i].len))
			continue;
		return section_defs[i].prog_type;
	}
	return -1;
}

class iu_prog; // forward declaration

static int debug = 0;
static std::unordered_map<int, std::unique_ptr<iu_prog>> progs;

static inline int64_t get_file_size(int fd)
{
	struct stat st;
	if (fstat(fd, &st) < 0) {
		perror("fstat");
		return -1;
	}

	return st.st_size;
}

template<typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline T val_from_buf(const unsigned char *buf)
{
	return *(const T *)(buf);
}

template<typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline void val_to_buf(unsigned char *buf, const T val)
{
	*(T *)(buf) = val;
}

static inline long bpf(__u64 cmd, union bpf_attr *attr, unsigned int size)
{
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
};

class iu_map {
	map_def def;
	int map_fd;
	const std::string name; // for debug msg

public:
	iu_map() = delete;
	iu_map(const Elf_Data *, Elf64_Addr, Elf64_Off, const char *);
	~iu_map();

	int create(const std::string &);

	friend class iu_prog; // for debug msg
};

iu_map::iu_map(const Elf_Data *data, Elf64_Addr base, Elf64_Off off,
		const char *c_name) : map_fd(-1), name(c_name)
{
	this->def = *(map_def *)((unsigned char *)data->d_buf + off - base);

	if (debug) {
		std::clog << "sym_name=" << c_name << std::endl;
		std::clog << "map_type=" << this->def.map_type << std::endl;
		std::clog << "key_size=" << this->def.key_size << std::endl;
		std::clog << "val_size=" << this->def.val_size << std::endl;
		std::clog << "max_size=" << this->def.max_size << std::endl;
		std::clog << "map_flag=" << this->def.map_flag << std::endl;
	}
}

iu_map::~iu_map()
{
	if (map_fd >= 0)
		close(map_fd);
}

int iu_map::create(const std::string &name)
{
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

	this->map_fd = (int)bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	return this->map_fd;
}

class iu_prog {
	struct subprog {
		std::string name;
		int prog_type;
		Elf64_Off offset;
		int fd;

		subprog() = delete;
		subprog(const char *nm, int prog_ty, Elf64_Off off) : name(nm), 
			prog_type(prog_ty), offset(off), fd(-1) {}
		~subprog() = default;
	};

	std::unordered_map<Elf64_Off, iu_map> map_defs;
	std::unordered_map<std::string, const iu_map *> name2map;
	std::vector<std::pair<Elf64_Sym *, std::string>> map_ptrs;
	std::unordered_map<std::string, subprog> subprogs;

	Elf *elf;
	Elf_Scn *symtab_scn;
	Elf_Scn *maps_scn;
	size_t file_size;
	unsigned char *file_map;
	int prog_fd;

	int parse_scns();
	int parse_maps();
	int parse_subprogs();

public:
	iu_prog() = delete;
	explicit iu_prog(const char *);
	iu_prog(const iu_prog &) = delete;
	iu_prog(iu_prog &&) = delete;
	~iu_prog();

	iu_prog &operator=(const iu_prog &) = delete;
	iu_prog &operator=(iu_prog &&) = delete;

	// Making this a separate function to avoid exceptions in constructor
	int parse_elf();

	int fix_maps();
	int load(unsigned);
	int find_map_by_name(const char *) const;
	int find_subprog_by_name(const char *) const;
};

iu_prog::iu_prog(const char *c_path) : map_defs(), map_ptrs(),
	symtab_scn(nullptr), maps_scn(nullptr), prog_fd(-1)
{
	int fd = open(c_path, 0, O_RDONLY);
	this->elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	file_size = get_file_size(fd);
	// FIXME probably going to corrupt original file
	file_map = (unsigned char *)mmap(NULL, file_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE, fd, 0);
	close(fd);
}

iu_prog::~iu_prog()
{
	if (this->elf)
		elf_end(this->elf);

	if (file_map)
		munmap(file_map, file_size);

	if (prog_fd >= 0)
		close(prog_fd);
}

int iu_prog::parse_scns()
{
	size_t shstrndx;

	if(elf_getshdrstrndx(elf, &shstrndx)) {
		std::cerr << "elf: failed to get section names section index"
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

		if (sh->sh_type == SHT_SYMTAB)
			this->symtab_scn = scn;
		else if (!strcmp(".maps", name))
			this->maps_scn = scn;
	}

	if (!this->maps_scn && debug) {
		std::clog << "section .maps not found" << std::endl;
	}

	return 0;
}

int iu_prog::parse_maps()
{
	Elf_Data *maps, *syms;
	int nr_syms, nr_maps = 0, maps_shndx;
	size_t strtabidx;
	Elf64_Addr maps_shaddr;

	if (!this->maps_scn) {
		return 0;
	}

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
		Elf64_Sym *sym = (Elf64_Sym *)syms->d_buf + i;
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
			map_defs.try_emplace(sym->st_value, maps, maps_shaddr,
					sym->st_value, name);
		} else if (sym->st_size == sizeof(struct map_def *)) {
			map_ptrs.emplace_back(sym, name);
		}

		nr_maps++;
	}

	if (debug)
		std::clog << "# of symbols in \".maps\": " << nr_maps << std::endl;

	return 0;
}

// get sec name
// get function symbols
int iu_prog::parse_subprogs()
{
	size_t shstrndx, strtabidx;
	Elf_Data *syms;
	int nr_syms;
	
	strtabidx = elf64_getshdr(symtab_scn)->sh_link;

	if (elf_getshdrstrndx(elf, &shstrndx)) {
		std::cerr << "elf: failed to get section names section index"
			<< std::endl;                                                       
		return -1; 	
	}

	syms = elf_getdata(symtab_scn, 0);
	
	if (!syms) {
		std::cerr << "elf: failed to get symbol definitions" << std::endl;
		return -1;
    }

	nr_syms = syms->d_size / sizeof(Elf64_Sym);

	for (int i = 0; i < nr_syms; i++) {
		Elf64_Sym *sym = (Elf64_Sym *)syms->d_buf + i;
		Elf_Scn *scn = elf_getscn(this->elf, sym->st_shndx);
		char *scn_name, *sym_name;

		if (!scn || ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
			continue;

		scn_name = elf_strptr(this->elf, shstrndx, 
				elf64_getshdr(scn)->sh_name);
		
		int prog_type = find_sec_def(scn_name);
		if (prog_type < 0)
			continue;
		
		sym_name = elf_strptr(elf, strtabidx, sym->st_name);

		if (debug) {
			std::clog << "section: " << scn_name << std::endl;
			std::clog << "symbol: " << sym_name << std::endl;
		}

		subprogs.try_emplace(sym_name, sym_name, prog_type, sym->st_value);
	}
	return 0;
};
int iu_prog::parse_elf()
{
	int ret;

	if (!elf) {
		std::cerr << "elf: failed to open object" << std::endl;
		return -1;
	}

	ret = this->parse_scns();
	ret = ret < 0 ? : this->parse_maps();
	ret = ret < 0 ? : this->parse_subprogs();

	return ret;
}

int iu_prog::fix_maps()
{
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

	if (this->file_size < 0 || (int64_t)this->file_map < 0) {
		perror("mmap");
		return -1;
	}

	for (const auto &ptr: map_ptrs) {
		size_t pos = ptr.first->st_value - maps_shaddr + maps_shoff;
		uint64_t map_addr = val_from_buf<uint64_t>(&this->file_map[pos]);
		const auto it = map_defs.find(map_addr);
		int map_fd;

		if (it == map_defs.end()) {
			std::cerr << "map def not found" << std::endl;
			continue;
		}

		if (debug) {
			std::clog << "map_ptr=0x" << std::hex << map_addr << std::dec
				<< std::endl;
			std::clog << "pointed obj name: " << it->second.name << std::endl;
			std::clog << "map_ptr_offset=0x" << std::hex
				<< ptr.first->st_value << std::dec << std::endl;
		}

		map_fd = it->second.create(ptr.second);
		if (map_fd < 0) {
			perror("bpf_map_create");
			return -1;
		}

		name2map.insert(std::make_pair(std::string(ptr.second), &it->second));

		if (debug)
			std::clog << "map_fd=" << map_fd << std::endl;

		val_to_buf<uint64_t>(&this->file_map[pos], map_fd);
	}

	return 0;
}

int iu_prog::load(unsigned prog_type)
{
	int fd;
	auto arr = std::make_unique<uint64_t[]>(map_ptrs.size());
	union bpf_attr attr, sp_attr;
	int idx = 0, ret = 0;

	// TODO: Will have race condition if multiple progs loaded at same time
	std::ofstream output("rust.out", std::ios::out | std::ios::binary);

	output.write((char *)this->file_map, this->file_size);
	output.close();

	fd = open("rust.out", O_RDONLY);

	for (auto &it: map_ptrs) {
		arr[idx++] = it.first->st_value;
	}

	memset(&attr, 0, sizeof(attr));

	attr.prog_type = BPF_PROG_TYPE_IU_BASE;
	memcpy(attr.prog_name, "map_test", sizeof("map_test"));
	attr.rustfd = fd;
	attr.license = (__u64)"GPL";

	attr.map_offs = (__u64)arr.get();
	attr.map_cnt = map_ptrs.size();

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

	for (auto &it: subprogs) {
		memset(&sp_attr, 0, sizeof(sp_attr));
		attr.prog_type = it.second.prog_type;
		strncpy(attr.prog_name, it.second.name.c_str(),
				sizeof(attr.prog_name) - 1);
		attr.base_prog_fd = this->prog_fd;
		attr.prog_offset = it.second.offset;
		attr.license = (__u64)"GPL";
		it.second.fd = bpf(BPF_PROG_LOAD_IU, &attr, sizeof(attr));
		
		if (it.second.fd < 0) {
			perror("bpf_prog_load_iu");
			goto close_fds;
		}

		if (debug)
			std::clog << "Program " << it.first << " loaded, fd = "
				<< it.second.fd << std::endl;
	}

	return ret;

close_fds:
	for (auto &it: subprogs) {
		if (it.second.fd >= 0)
			close(it.second.fd);
	}
	close(this->prog_fd);
	return -1;
}

int iu_prog::find_map_by_name(const char *name) const
{
	auto it = name2map.find(name);
	return it != name2map.end() ? it->second->map_fd : -1;
}

int iu_prog::find_subprog_by_name(const char *name) const
{
	auto it = subprogs.find(name);
	return it != subprogs.end() ? it->second.fd : -1;
}

} // end anynomous namespace

void iu_set_debug(const int val)
{
	debug = val;
}

int iu_prog_load(const char *file_path, unsigned prog_type)
{
	int ret;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		std::cerr << "elf: failed to init libelf" << std::endl;
		return -1;
	}

	auto prog = std::make_unique<iu_prog>(file_path);

	ret = prog->parse_elf();
	ret = ret ? : prog->fix_maps();
	ret = ret ? : prog->load(prog_type);

	if (ret >= 0)
		progs[ret] = std::move(prog);

	return ret;
}

int iu_prog_close(int prog_fd)
{
	auto it = progs.find(prog_fd);
	if (it != progs.end()) {
		progs.erase(it);
		return 0;
	}

	return -1;
}

int iu_prog_get_map(int prog_fd, const char *map_name)
{
	auto it = progs.find(prog_fd);
	return it != progs.end() ? it->second->find_map_by_name(map_name) : -1;
}

int iu_prog_get_subprog(int prog_fd, const char *subprog_name)
{
	auto it = progs.find(prog_fd);
	return it != progs.end() ?
		it->second->find_subprog_by_name(subprog_name) : -1;
}
