#ifndef LIBREX_H
#define LIBREX_H

#ifdef __cplusplus
extern "C" {
#endif

struct bpf_object;
struct bpf_object_open_opts;

void rex_set_debug(const int val);

int rex_obj_load(const char *file_path, struct bpf_object *obj);
int rex_obj_close(int prog_fd);
int rex_obj_get_map(int prog_fd, const char *map_name);
int rex_obj_get_prog(int prog_fd, const char *prog_name);

struct bpf_object *rex_object__open(char *path);
struct bpf_object *rex_object__open_file(char *path, const struct bpf_object_open_opts *opts);

#ifdef __cplusplus
}
#endif

#endif // LIBREX_H
