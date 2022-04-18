#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <type_traits>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/unistd.h>

#include <libelf.h>

#include "libiu.h"

#define BPF_PROG_LOAD_DJW 0x1234beef

namespace { // begin anynomous namespace

static int debug = 0;

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
	int fd;
	const std::string name; // for debug msg

public:
	iu_map() = delete;
	iu_map(const Elf_Data *, Elf64_Addr, Elf64_Off, const char *);
	~iu_map() = default;

	int create(const std::string &name);

	friend class iu_prog; // for debug msg
};

iu_map::iu_map(const Elf_Data *data, Elf64_Addr base, Elf64_Off off,
		const char *c_name) : fd(-1), name(c_name)
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

	this->fd = (int)bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	return this->fd;
}

class iu_prog {
	std::unordered_map<Elf64_Off, iu_map> map_defs;
	std::vector<std::pair<Elf64_Sym *, std::string>> map_ptrs;
	Elf *elf;
	Elf_Scn *symtab_scn;
	Elf_Scn *maps_scn;
	size_t file_size;
	unsigned char *file_map;
	int prog_fd;

	int parse_scns();
	int parse_maps();

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
	int load();
};

iu_prog::iu_prog(const char *c_path) : map_defs(), map_ptrs(),
	symtab_scn(nullptr), maps_scn(nullptr), prog_fd(-1)
{
	int fd = open(c_path, 0, O_RDONLY);
	this->elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	file_size = get_file_size(fd);
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

		name = elf_strptr(elf, shstrndx, sh->sh_name);

		if (!name) {
			std::cerr << "nelf: failed to get section name" << std::endl;
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

int iu_prog::parse_elf()
{
	int ret;

	if (!elf) {
		std::cerr << "elf: failed to open object" << std::endl;
		return -1;
	}

	ret = this->parse_scns();
	ret = ret < 0 ? : this->parse_maps();

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

		if (debug)
			std::clog << "map_fd=" << map_fd << std::endl;

		val_to_buf<uint64_t>(&this->file_map[pos], map_fd);
	}

	return 0;
}

int iu_prog::load()
{
	int fd;
	auto arr = std::make_unique<uint64_t[]>(map_ptrs.size());
	union bpf_attr attr;
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

	attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
	memcpy(attr.prog_name, "map_test", sizeof("map_test"));
	attr.rustfd = fd;
	attr.license = (__u64)"GPL";

	attr.map_offs = (__u64)arr.get();
	attr.map_cnt = map_ptrs.size();

	ret = bpf(BPF_PROG_LOAD_DJW, &attr, sizeof(attr));

	if (ret < 0) {
		perror("bpf_prog_load");
		ret = -1;
	}

	if (remove("rust.out") < 0) {
		perror("remove");
		ret = -1;
	}

	return ret;
}

} // end anynomous namespace

void iu_set_debug(const int val)
{
	debug = val;
}

int iu_prog_load(const char *file_path)
{
	int ret;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		std::cerr << "elf: failed to init libelf" << std::endl;
		return 1;
	}

	iu_prog prog(file_path);

	ret = prog.parse_elf();
	ret = ret ? : prog.fix_maps();
	ret = ret ? : prog.load();

	return ret;
}
