#ifndef LIBREX_H
#define LIBREX_H

struct bpf_object;
struct rex_obj;

#ifdef __cplusplus
extern "C" {
#endif

void rex_set_debug(int val);

[[nodiscard]] struct rex_obj *rex_obj_load(const char *file_path);

[[nodiscard]] struct bpf_object *rex_obj_get_bpf(struct rex_obj *obj);

#ifdef __cplusplus
}
#endif

#endif // LIBREX_H
