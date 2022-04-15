#include <cerrno>
#include <cstring>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>
#include <unordered_set>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/unistd.h>

#include <libelf.h>

#define EXE "./target/debug/map_test"

#define BPF_PROG_LOAD_DJW 0x1234beef

namespace { // begin anynomous namespace

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

struct iu_map {
	const std::string name;
	const Elf64_Off offset;
	map_def def;
	int fd;

	iu_map() = delete;
	iu_map(char *c_name, Elf64_Off off) : name(c_name), offset(off), def({ 0 }), fd(-1) {}
	~iu_map() = default;
};


static int collect_map_def(const Elf_Data &data, iu_map &map_obj, Elf64_Addr base)
{
	Elf64_Off offset = map_obj.offset;
	map_def *def = reinterpret_cast<map_def *>((unsigned char *)data.d_buf + offset - base);

	std::cerr << "map_name=" << map_obj.name << std::endl;
	std::cerr << "map_type=" << def->map_type << std::endl;
	std::cerr << "key_size=" << def->key_size << std::endl;
	std::cerr << "val_size=" << def->val_size << std::endl;
	std::cerr << "max_size=" << def->max_size << std::endl;
	std::cerr << "map_flag=" << def->map_flag << std::endl;

	map_obj.def = *def;

	return 0;
}

static size_t get_file_size(int fd)
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
	return *reinterpret_cast<const T *>(buf);
}

template<typename T, std::enable_if_t<std::is_integral<T>::value, bool> = true>
static inline void val_to_buf(unsigned char *buf, const T val)
{
	*reinterpret_cast<T *>(buf) = val;
}

static inline long bpf(__u64 cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static long map_create(const iu_map &map_obj)
{
	const auto &def = map_obj.def;
	const auto &name = map_obj.name;

	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));

	attr.map_type = def.map_type;
	attr.key_size = def.key_size;
	attr.value_size = def.val_size;
	attr.max_entries = def.max_size;
	attr.map_flags = def.map_flag;

	if (name.size() < BPF_OBJ_NAME_LEN)
		memcpy(attr.map_name, name.c_str(), name.size());

	return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	//return 0x1122334455667788;
}

static long prog_load(const char *file,
		const std::unordered_map<Elf64_Sym *, std::string> &map_ptrs)
{
	int fd = open(file, O_RDONLY);
	auto arr = std::make_unique<uint64_t[]>(map_ptrs.size());
	union bpf_attr attr;
	int idx = 0;

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

	return bpf(BPF_PROG_LOAD_DJW, &attr, sizeof(attr));
}

static inline long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
							int cpu, int  group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

} // end anynomous namespace


int main(void)
{
	int fd, idx = 0, maps_shndx = -1, nr_syms, nr_maps = 0, i;
	Elf *elf;
	Elf_Data *data, *symbols;
	Elf_Scn *scn = NULL;
	Elf64_Shdr *sh = NULL;
	size_t shstrndx, strtabidx;;
	char *name;
	std::unordered_map<Elf64_Off, iu_map> map_defs;
	std::unordered_map<Elf64_Sym *, std::string> map_ptrs;
	unsigned char *file_map;
	size_t file_size;
	int prog_fd, trace_id_fd, perf_event_fd, trace_pipe_fd;
	char config_str[256];
	struct perf_event_attr p_attr;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "failed to init libelf");
		return 1;
	}

	fd = open(EXE, 0, O_RDONLY);
	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);

	if (!elf) {
		std::cerr << "failed to open object" << std::endl;
		return 1;
	}

	if(elf_getshdrstrndx(elf, &shstrndx)) {
		std::cerr << "elf: failed to get section names section index"
				  << std::endl;
		return 1;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		idx = elf_ndxscn(scn);
		sh = elf64_getshdr(scn);
		if (!sh)
			return 1;

		if (sh->sh_type == SHT_SYMTAB) {
			data = elf_getdata(scn, 0);
			if (!data)
				return 1;

			symbols = data;
			strtabidx = sh->sh_link;
		}
		name = elf_strptr(elf, shstrndx, sh->sh_name);
		if (!name) {
			std::cerr << "name failed" << std::endl;
			return 1;
		}

		// std::cerr << "index " << idx << ": " << name << std::endl;

		if (!strcmp(".maps", name)) {
			maps_shndx = idx;
		}
	}

	scn = elf_getscn(elf, maps_shndx);
	data = elf_getdata(scn, 0);

	if (!scn || !data) {
		std::cerr << "elf: failed to get map definitions" << std::endl;
		return 1;
	}

	/*
	 * Count number of maps. Each map has a name.
	 * Array of maps is not supported: only the first element is
	 * considered.
	 *
	 * TODO: Detect array of map and report error.
	 */
	nr_syms = symbols->d_size / sizeof(Elf64_Sym);
	for (i = 0; i < nr_syms; i++) {
		Elf64_Sym *sym = (Elf64_Sym *)symbols->d_buf + i;

		if (sym->st_shndx != maps_shndx)
			continue;
		if (ELF64_ST_TYPE(sym->st_info) != STT_OBJECT)
			continue;
		nr_maps++;
		name = elf_strptr(elf, strtabidx, sym->st_name);
		std::cerr << "symbol: " << name << ", st_value=0x" << std::hex
				  << sym->st_value << ", st_size=" << std::dec << sym->st_size
				  << std::endl;

		if (sym->st_size == sizeof(struct map_def))
			map_defs.insert(std::make_pair(sym->st_value, iu_map(name, sym->st_value)));
		else if (sym->st_size == sizeof(struct map_def *))
			map_ptrs.insert(std::make_pair(sym, name));
		else
			std::cerr << "invalid size in .map section" << std::endl;
	}

	std::cerr << "# of symbols in \".maps\": " << nr_maps << std::endl;

	std::cerr << ".maps section file offset=0x" << std::hex
			  << elf64_getshdr(scn)->sh_offset << std::dec << std::endl;

	for (auto &def: map_defs) {
		collect_map_def(*data, def.second, elf64_getshdr(scn)->sh_addr);
	}

	std::cerr << "file_size=0x" << std::hex << get_file_size(fd) << std::dec
			  << std::endl;

	file_size = get_file_size(fd);
	file_map = (unsigned char *)mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	for (const auto &ptr: map_ptrs) {
		size_t pos = ptr.first->st_value - elf64_getshdr(scn)->sh_addr + elf64_getshdr(scn)->sh_offset;
		const auto it = map_defs.find(val_from_buf<uint64_t>(&file_map[pos]));
		int64_t map_fd;

		if (it == map_defs.end()) {
			std::cerr << "map def not found" << std::endl;
			continue;
		}

		std::cerr << "map_ptr=0x" << std::hex << val_from_buf<uint64_t>(&file_map[pos]) << std::dec << std::endl;
		std::cerr << "pointed map name: " << it->second.name << std::endl;
		std::cerr << "map_ptr_offset=0x" << std::hex << ptr.first->st_value << std::dec << std::endl;

		map_fd = map_create(it->second);
		if (map_fd < 0) {
			perror("bpf_map_create");
			exit(1);
		}
		std::cerr << "map_fd=" << map_fd << std::endl;

		val_to_buf<uint64_t>(&file_map[pos], map_fd);
	}

	std::ofstream output("rust.out", std::ios::out | std::ios::binary);
	output.write((char *)file_map, file_size);
	output.close();

	// PROG LOAD & ATTACHMENT
	prog_fd = prog_load("rust.out", map_ptrs);
	if (prog_fd < 0) {
		perror("bpf_prog_load");
		exit(1);
	}

	trace_id_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/events/syscalls/sys_enter_dup/id", O_RDONLY);
	if (trace_id_fd < 0) {
		perror("openat(/sys/kernel/debug/tracing/events/syscalls/sys_enter_dup/id)");
		exit(1);
	}
	read(trace_id_fd, config_str, 256);
	close(trace_id_fd);

	memset(&p_attr, 0, sizeof(p_attr));
	p_attr.type = PERF_TYPE_TRACEPOINT;
	p_attr.size = PERF_ATTR_SIZE_VER5;
	p_attr.config = atoi(config_str);
	perf_event_fd = perf_event_open(&p_attr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
	if (perf_event_fd < 0) {
		perror("perf_event_open");
		exit(1);
	}

	ioctl(perf_event_fd, PERF_EVENT_IOC_SET_BPF, prog_fd);
	ioctl(perf_event_fd, PERF_EVENT_IOC_ENABLE, 0);

	trace_pipe_fd = openat(AT_FDCWD, "/sys/kernel/debug/tracing/trace_pipe", O_RDONLY);

	for (;;) {
        char c;
        if (read(trace_pipe_fd, &c, 1) == 1)
            putchar(c);
    }

	return 0;
}
